/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package svd;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.xml.parsers.ParserConfigurationException;

import org.xml.sax.SAXException;

import docking.widgets.OptionDialog;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.ProgramBasedDataTypeManager;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedLongDataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
import io.svdparser.SvdAddressBlock;
import io.svdparser.SvdDevice;
import io.svdparser.SvdParserException;
import io.svdparser.SvdPeripheral;
import io.svdparser.SvdRegister;
import svd.MemoryUtils.MemRangeRelation;

public class SvdLoadTask extends Task {
	private File mSvdFile;
	private Program mProgram;
	private Memory mMemory;
	private SymbolTable mSymTable;

	public SvdLoadTask(Program program, File svdFile) {
		super("Load SVD", true, false, true, true);
		mSvdFile = svdFile;
		mProgram = program;
		mMemory = program.getMemory();
		mSymTable = program.getSymbolTable();
	}

	@Override
	public void run(TaskMonitor monitor) throws CancelledException {
		monitor.setMessage("Loading " + mSvdFile.getPath() + "...");
		monitor.checkCancelled();

		SvdDevice device;
		try {
			device = SvdDevice.fromFile(mSvdFile);
		} catch (SvdParserException | SAXException | IOException | ParserConfigurationException e) {
			Msg.error(getClass(), "Unable to load SVD file!", e);
			return;
		}

		monitor.setMessage("Creating candidate blocks from SVD file...");
		monitor.checkCancelled();
		Map<Block, BlockInfo> blocks = createBlocksFromDevice(device);

		for (BlockInfo blockInfo : blocks.values()) {
			monitor.setMessage("Processing " + blockInfo.name + "...");
			monitor.checkCancelled();
			processBlock(blockInfo);
		}
	}

	private Map<Block, BlockInfo> createBlocksFromDevice(SvdDevice device) {
		Map<Block, BlockInfo> blocks = new HashMap<Block, BlockInfo>();

		// Convert all peripherals to blocks...
		for (SvdPeripheral periph : device.getPeripherals()) {
			for (SvdAddressBlock block : periph.getAddressBlocks()) {
				// Create a block..
				Block b = new Block(periph.getBaseAddr() + block.getOffset(), block.getSize());

				// Check if block exists...
				BlockInfo bInfo = blocks.get(b);
				if (bInfo == null)
					bInfo = new BlockInfo();

				// Fill in block info...
				if (bInfo.block == null)
					bInfo.block = b;
				String name = getPeriphBlockName(periph, block);
				if (bInfo.name == null)
					bInfo.name = name;
				else
					bInfo.name += "/" + name;
				bInfo.isReadable = true;
				bInfo.isWritable = true;
				bInfo.isExecutable = name.contains("RAM") || name.contains("memory");
				bInfo.isVolatile = !bInfo.isExecutable;
				bInfo.peripherals.add(periph);

				// Save the data...
				blocks.put(b, bInfo);
			}
		}
		return blocks;
	}

	private String getPeriphBlockName(SvdPeripheral periph, SvdAddressBlock block) {
		String name = periph.getName();
		String blockUsage = block.getUsage();
		if (blockUsage != null && !blockUsage.isEmpty() && !blockUsage.contains("registers")) {
			name += "_" + blockUsage;
		}
		return name;
	}

	private void processBlock(BlockInfo blockInfo) {
		boolean memOk = processBlockMemory(blockInfo);
		if (memOk) {
			processBlockSymbol(blockInfo);
			processBlockDataTypes(blockInfo);
			// Add SVD comments to existing instructions
			addSvdCommentsToInstructions(blockInfo);
		}
	}

	private boolean processBlockMemory(BlockInfo blockInfo) {
		MemoryBlock[] collidingMemoryBlocks = MemoryUtils.getBlockCollidingMemoryBlocks(mMemory, blockInfo.block);
		if (collidingMemoryBlocks.length == 0) {
			createMemoryBlock(blockInfo);
		} else if (collidingMemoryBlocks.length == 1 && MemoryUtils.getMemoryBlockRelation(collidingMemoryBlocks[0],
				blockInfo.block) == MemRangeRelation.RANGES_ARE_EQUAL) {
			updateMatchingMemoryBlock(collidingMemoryBlocks[0], blockInfo);
		} else {
			Msg.showWarn(getClass(), null, "Load SVD", "Could not create a region for " + blockInfo.name + "@"
					+ String.format("0x%08x", blockInfo.block.getAddress()) + "+"
					+ String.format("0x%08x", blockInfo.block.getSize()) + ". It conflicts with an existing region!");
			return false;
		}
		return true;
	}

	private void createMemoryBlock(BlockInfo blockInfo) {
		AddressSpace addrSpace = mProgram.getAddressFactory().getDefaultAddressSpace();
		Address addr = addrSpace.getAddress(blockInfo.block.getAddress());
		int transactionId = mProgram.startTransaction("SVD memory block creation");
		boolean ok = false;
		try {
			MemoryBlock memBlock = mMemory.createUninitializedBlock(blockInfo.name, addr, blockInfo.block.getSize().longValue(),
					false);
			memBlock.setRead(blockInfo.isReadable);
			memBlock.setWrite(blockInfo.isWritable);
			memBlock.setExecute(blockInfo.isExecutable);
			memBlock.setVolatile(blockInfo.isVolatile);
			memBlock.setComment("Generated by Device Tree Blob");
			ok = true;
		} catch (LockException e) {
			Msg.showError(this, null, getTaskTitle(), e, e);
		} catch (MemoryConflictException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalArgumentException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (AddressOverflowException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		mProgram.endTransaction(transactionId, ok);
	}

	private void updateMatchingMemoryBlock(MemoryBlock collidingMemoryBlock, BlockInfo blockInfo) {
		if (!collidingMemoryBlock.getName().equals(blockInfo.name)
				&& OptionDialog.showYesNoDialog(null, "Load SVD",
						"An existing memory block with name \"" + collidingMemoryBlock.getName()
								+ "\" is in the same region as the \"" + blockInfo.name
								+ "\" peripheral. Do you want to rename it to \"" + blockInfo.name
								+ "\"?") == OptionDialog.OPTION_ONE) {
			int transactionId = mProgram.startTransaction("SVD memory block rename");
			boolean ok = false;
			try {
				collidingMemoryBlock.setName(blockInfo.name);
				collidingMemoryBlock.setComment("Changed by Device Tree Blob");
				ok = true;
			} catch (IllegalArgumentException | LockException e) {
				e.printStackTrace();
			}
			mProgram.endTransaction(transactionId, ok);
		}
		if (collidingMemoryBlock.isRead() != blockInfo.isReadable && OptionDialog.showYesNoDialog(null,
				"Load SVD",
				"Memory block \"" + collidingMemoryBlock.getName() + "\" is marked as"
						+ ((!collidingMemoryBlock.isRead()) ? " non" : "")
						+ " readable. The SVD file suggests it should be"
						+ (collidingMemoryBlock.isRead() ? " non" : "") + " readable. Do you want to changee it to"
						+ (collidingMemoryBlock.isRead() ? " non" : "") + " readable?") == OptionDialog.OPTION_ONE) {
			int transactionId = mProgram
					.startTransaction("SVD " + collidingMemoryBlock.getName() + " memory block property change");
			boolean ok = false;
			try {
				collidingMemoryBlock.setRead(blockInfo.isReadable);
				collidingMemoryBlock.setComment("Changed by Device Tree Blob");
				ok = true;
			} catch (IllegalArgumentException e) {
				e.printStackTrace();
			}
			mProgram.endTransaction(transactionId, ok);
		}

		if (collidingMemoryBlock.isWrite() != blockInfo.isWritable && OptionDialog.showYesNoDialog(null,
				"Load SVD",
				"Memory block \"" + collidingMemoryBlock.getName() + "\" is marked as"
						+ ((!collidingMemoryBlock.isWrite()) ? " non" : "")
						+ " writable. The SVD file suggests it should be"
						+ (collidingMemoryBlock.isWrite() ? " non" : "") + " writable. Do you want to changee it to"
						+ (collidingMemoryBlock.isWrite() ? " non" : "") + " writable?") == OptionDialog.OPTION_ONE) {
			int transactionId = mProgram
					.startTransaction("SVD " + collidingMemoryBlock.getName() + " memory block property change");
			boolean ok = false;
			try {
				collidingMemoryBlock.setWrite(blockInfo.isWritable);
				collidingMemoryBlock.setComment("Changed by Device Tree Blob");
				ok = true;
			} catch (IllegalArgumentException e) {
				e.printStackTrace();
			}
			mProgram.endTransaction(transactionId, ok);
		}

		if (collidingMemoryBlock.isExecute() != blockInfo.isExecutable && OptionDialog.showYesNoDialog(null,
				"Load SVD",
				"Memory block \"" + collidingMemoryBlock.getName() + "\" is marked as"
						+ ((!collidingMemoryBlock.isExecute()) ? " non" : "")
						+ " executable. The SVD file suggests it should be"
						+ (collidingMemoryBlock.isExecute() ? " non" : "") + " executable. Do you want to changee it to"
						+ (collidingMemoryBlock.isExecute() ? " non" : "")
						+ " executable?") == OptionDialog.OPTION_ONE) {
			int transactionId = mProgram
					.startTransaction("SVD " + collidingMemoryBlock.getName() + " memory block property change");
			boolean ok = false;
			try {
				collidingMemoryBlock.setExecute(blockInfo.isExecutable);
				collidingMemoryBlock.setComment("Changed by Device Tree Blob");
				ok = true;
			} catch (IllegalArgumentException e) {
				e.printStackTrace();
			}
			mProgram.endTransaction(transactionId, ok);
		}

		if (collidingMemoryBlock.isVolatile() != blockInfo.isVolatile && OptionDialog.showYesNoDialog(null,
				"Load SVD",
				"Memory block \"" + collidingMemoryBlock.getName() + "\" is marked as"
						+ ((!collidingMemoryBlock.isVolatile()) ? " non" : "")
						+ " volatile. The SVD file suggests it should be"
						+ (collidingMemoryBlock.isVolatile() ? " non" : "") + " volatile. Do you want to changee it to"
						+ (collidingMemoryBlock.isVolatile() ? " non" : "")
						+ " volatile?") == OptionDialog.OPTION_ONE) {
			int transactionId = mProgram
					.startTransaction("SVD " + collidingMemoryBlock.getName() + " memory block property change");
			boolean ok = false;
			try {
				collidingMemoryBlock.setVolatile(blockInfo.isVolatile);
				collidingMemoryBlock.setComment("Changed by Device Tree Blob");
				ok = true;
			} catch (IllegalArgumentException e) {
				e.printStackTrace();
			}
			mProgram.endTransaction(transactionId, ok);
		}
	}

	private void processBlockSymbol(BlockInfo blockInfo) {
		// Calculate address of the block...
		AddressSpace addrSpace = mProgram.getAddressFactory().getDefaultAddressSpace();
		Address addr = addrSpace.getAddress(blockInfo.block.getAddress().longValue());

		// Create a symbol name...
		Namespace namespace = getOrCreateNamespace("Peripherals");
		int transactionId = mProgram.startTransaction("SVD " + blockInfo.name + " symtable creation");
		boolean ok = false;
		try {
			mSymTable.createLabel(addr, blockInfo.name.replace('/', '_'), namespace, SourceType.IMPORTED);
			ok = true;
		} catch (InvalidInputException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		mProgram.endTransaction(transactionId, ok);
	}

	private Namespace getOrCreateNamespace(String name) {
		Namespace namespace = mSymTable.getNamespace(name, null);
		if (namespace != null)
			return namespace;

		int transactionId = mProgram.startTransaction("SVD " + name + " namespace creation");
		boolean ok = false;
		try {
			namespace = mSymTable.createNameSpace(null, name, SourceType.IMPORTED);
			ok = true;
		} catch (DuplicateNameException | InvalidInputException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		mProgram.endTransaction(transactionId, ok);
		return namespace;
	}

	private void processBlockDataTypes(BlockInfo blockInfo) {
		StructureDataType struct = createPeripheralBlockDataType(blockInfo);

		// Add struct to the data type manager...
		ProgramBasedDataTypeManager dataTypeManager = mProgram.getDataTypeManager();
		int transactionId = mProgram.startTransaction("SVD " + blockInfo.name + " data type creation");
		boolean ok = false;
		try {
			dataTypeManager.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER);
			ok = true;
		} catch (IllegalArgumentException e) {
			e.printStackTrace();
		}
		mProgram.endTransaction(transactionId, ok);

		// Calculate address of the block...
		AddressSpace addrSpace = mProgram.getAddressFactory().getDefaultAddressSpace();
		Address addr = addrSpace.getAddress(blockInfo.block.getAddress().longValue());

		// Add data type to listing (only if no conflicting data exists)...
		Listing listing = mProgram.getListing();
		transactionId = mProgram.startTransaction("SVD " + blockInfo.name + " data type listing placement");
		ok = false;
		try {
			// Check if there's already data at this address
			if (listing.getDataAt(addr) == null && listing.getInstructionAt(addr) == null) {
				listing.createData(addr, struct);
				Msg.info(getClass(), "Created data structure for " + blockInfo.name + " at " + addr);
			} else {
				Msg.info(getClass(), "Skipped data structure creation for " + blockInfo.name + " at " + addr + " - conflicting data exists");
			}
			ok = true;
		} catch (CodeUnitInsertionException e) {
			Msg.warn(getClass(), "Could not create data structure for " + blockInfo.name + " at " + addr + ": " + e.getMessage());
			ok = true; // Don't fail the entire transaction for data creation conflicts
		} catch (Exception e) {
			Msg.error(getClass(), "Unexpected error creating data structure for " + blockInfo.name + " at " + addr, e);
			ok = true;
		}
		mProgram.endTransaction(transactionId, ok);
	}

	private StructureDataType createPeripheralBlockDataType(BlockInfo blockInfo) {
		String struct_name = blockInfo.name.replace('/', '_') + "_reg_t";
		StructureDataType struct = new StructureDataType(struct_name, blockInfo.block.getSize().intValue());
		for (SvdPeripheral periph : blockInfo.peripherals)
			for (SvdRegister reg : periph.getRegisters())
				if (reg.getOffset() < blockInfo.block.getSize())
					struct.replaceAtOffset(reg.getOffset(), new UnsignedLongDataType(), reg.getSize() / 8,
							reg.getName(), reg.getDescription());
		return struct;
	}
	
	/**
	 * Process instructions in the program and add SVD-based comments
	 * for memory references that match SVD registers
	 */
	private void addSvdCommentsToInstructions(BlockInfo blockInfo) {
		addSvdCommentsToInstructions(blockInfo, true, false);
	}
	
	/**
	 * Process instructions in the program and add SVD-based comments
	 * for memory references that match SVD registers
	 * 
	 * @param blockInfo Block information containing peripherals and registers
	 * @param preserveExistingComments If true, append to existing comments; if false, replace them
	 * @param onlyCurrentBlock If true, only process instructions within the current block's address range
	 */
	private void addSvdCommentsToInstructions(BlockInfo blockInfo, boolean preserveExistingComments, boolean onlyCurrentBlock) {
		Listing listing = mProgram.getListing();
		AddressSpace addrSpace = mProgram.getAddressFactory().getDefaultAddressSpace();
		
		// Create a map of register addresses to their comprehensive information
		Map<Long, String> registerMap = new HashMap<>();
		for (SvdPeripheral periph : blockInfo.peripherals) {
			for (SvdRegister reg : periph.getRegisters()) {
				long regAddress = periph.getBaseAddr() + reg.getOffset();
				
				// Build comprehensive comment with peripheral and register info
				StringBuilder regInfo = new StringBuilder();
				
				// Start with peripheral.register name
				regInfo.append(periph.getName()).append(".").append(reg.getName());
				
				// Try to get peripheral description using reflection if available
				// TODO: retrieve peripheral description from SVD XML
				String periphDesc = "";
				String regDesc = reg.getDescription();
				
				// Build comment with peripheral description (if available) and register description
				if (periphDesc != null && !periphDesc.trim().isEmpty() && 
					regDesc != null && !regDesc.trim().isEmpty()) {
					// Both descriptions available - format: "Peripheral Desc - Register Desc"
					regInfo.append(" - ").append(periphDesc.trim())
						   .append(" - ").append(regDesc.trim());
				} else if (periphDesc != null && !periphDesc.trim().isEmpty()) {
					// Only peripheral description
					regInfo.append(" - ").append(periphDesc.trim());
				} else if (regDesc != null && !regDesc.trim().isEmpty()) {
					// Only register description
					regInfo.append(" - ").append(regDesc.trim());
				}
				
				// Add register size information for additional context
				int regSize = reg.getSize();
				if (regSize > 0) {
					regInfo.append(" [").append(regSize).append("-bit]");
				}
				
				// Add register offset information for reference
				long regOffset = reg.getOffset();
				regInfo.append(" @0x").append(String.format("%X", regOffset));
				
				// Note: Could add more info if available from SVD parser
				
				registerMap.put(regAddress, regInfo.toString());
			}
		}
		
		if (registerMap.isEmpty()) {
			return; // No registers to process
		}
		
		// Determine the address range to scan
		Address startAddr = null;
		Address endAddr = null;
		if (onlyCurrentBlock) {
			startAddr = addrSpace.getAddress(blockInfo.block.getAddress());
			// Calculate end address safely
			long endOffset = blockInfo.block.getAddress() + blockInfo.block.getSize() - 1;
			if (endOffset > addrSpace.getMaxAddress().getOffset()) {
				endAddr = addrSpace.getMaxAddress();
			} else {
				endAddr = addrSpace.getAddress(endOffset);
			}
		}
		
		// Scan instructions and add SVD comments
		int transactionId = mProgram.startTransaction("SVD comment addition for " + blockInfo.name);
		boolean ok = false;
		int commentsAdded = 0;
		try {
			// Iterate through instructions
			var instructionIterator = onlyCurrentBlock ? 
				listing.getInstructions(startAddr, true) : 
				listing.getInstructions(true);
				
			while (instructionIterator.hasNext()) {
				var instruction = instructionIterator.next();
				
				// If processing only current block, check if we're still in range
				if (onlyCurrentBlock && instruction.getAddress().compareTo(endAddr) > 0) {
					break;
				}
				
				// Check each operand for memory references
				for (int i = 0; i < instruction.getNumOperands(); i++) {
					var operandAddresses = instruction.getOperandReferences(i);
					for (var ref : operandAddresses) {
						if (ref.isMemoryReference()) {
							long targetAddr = ref.getToAddress().getOffset();
							
							// Check if this address matches any SVD register
							String regInfo = findMatchingRegister(targetAddr, registerMap);
							if (regInfo != null) {
								// Add comment to the instruction
								String existingComment = listing.getComment(CodeUnit.EOL_COMMENT, instruction.getAddress());
								String newComment = "SVD: " + regInfo;
								
								// Handle existing comments
								if (preserveExistingComments && existingComment != null && !existingComment.isEmpty()) {
									// Extract peripheral.register pattern from regInfo
									String periphRegPattern = extractPeriphRegPattern(regInfo);
									if (periphRegPattern != null && existingComment.contains("SVD: " + periphRegPattern)) {
										// Replace existing SVD comment with the new enhanced one
										// Remove old SVD comment pattern and add new one
										String updatedComment = removeOldSvdComment(existingComment, periphRegPattern);
										if (updatedComment.trim().isEmpty()) {
											newComment = newComment; // Only SVD comment
										} else {
											newComment = updatedComment + "; " + newComment;
										}
									} else {
										// No existing SVD comment for this register, append new one
										newComment = existingComment + "; " + newComment;
									}
								}
								
								listing.setComment(instruction.getAddress(), CodeUnit.EOL_COMMENT, newComment);
								commentsAdded++;
							}
						}
					}
				}
			}
			ok = true;
			Msg.info(getClass(), "Added " + commentsAdded + " SVD comments for " + blockInfo.name);
		} catch (Exception e) {
			Msg.error(getClass(), "Error adding SVD comments for " + blockInfo.name, e);
		}
		mProgram.endTransaction(transactionId, ok);
	}
	
	/**
	 * Find a matching register for the given address, with some tolerance
	 * for partial register accesses (byte/halfword accesses to word registers)
	 */
	private String findMatchingRegister(long targetAddr, Map<Long, String> registerMap) {
		// Exact match first
		if (registerMap.containsKey(targetAddr)) {
			return registerMap.get(targetAddr);
		}
		
		// Check for partial register access (e.g., byte access to 32-bit register)
		for (Map.Entry<Long, String> entry : registerMap.entrySet()) {
			long regAddr = entry.getKey();
			// Check if target address is within 4 bytes of register address
			if (targetAddr >= regAddr && targetAddr < regAddr + 4) {
				String regInfo = entry.getValue();
				long offset = targetAddr - regAddr;
				if (offset > 0) {
					regInfo += String.format(" (+0x%x)", offset);
				}
				return regInfo;
			}
		}
		
		return null;
	}
	
	/**
	 * Extract peripheral.register pattern from regInfo string
	 * @param regInfo The register info string (e.g., "GCLK.SYNCBUSY - Description...")
	 * @return The peripheral.register pattern (e.g., "GCLK.SYNCBUSY")
	 */
	private String extractPeriphRegPattern(String regInfo) {
		if (regInfo == null || regInfo.isEmpty()) {
			return null;
		}
		
		// Find the first " - " to extract the peripheral.register part
		int dashIndex = regInfo.indexOf(" - ");
		if (dashIndex > 0) {
			return regInfo.substring(0, dashIndex);
		}
		
		// If no dash found, check for the first space or bracket
		int spaceIndex = regInfo.indexOf(" ");
		if (spaceIndex > 0) {
			return regInfo.substring(0, spaceIndex);
		}
		
		return regInfo; // Return as-is if no separators found
	}
	
	/**
	 * Remove old SVD comment for a specific peripheral.register from existing comment
	 * @param existingComment The existing comment that may contain old SVD info
	 * @param periphRegPattern The peripheral.register pattern to remove (e.g., "GCLK.SYNCBUSY")
	 * @return The comment with the old SVD entry removed
	 */
	private String removeOldSvdComment(String existingComment, String periphRegPattern) {
		if (existingComment == null || existingComment.isEmpty() || periphRegPattern == null) {
			return existingComment;
		}
		
		// Split comment by semicolons to find individual comment parts
		String[] commentParts = existingComment.split(";");
		StringBuilder result = new StringBuilder();
		
		for (String part : commentParts) {
			String trimmedPart = part.trim();
			// Skip any SVD comment that contains our peripheral.register pattern
			if (!trimmedPart.startsWith("SVD: " + periphRegPattern)) {
				if (result.length() > 0) {
					result.append("; ");
				}
				result.append(trimmedPart);
			}
		}
		
		return result.toString();
	}
}
