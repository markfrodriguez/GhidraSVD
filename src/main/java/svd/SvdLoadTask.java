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
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.xml.parsers.ParserConfigurationException;

import org.xml.sax.SAXException;

import docking.widgets.OptionDialog;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.ProgramBasedDataTypeManager;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.WordDataType;
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
import io.svdparser.SvdEnumeratedValue;
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

		monitor.setMessage("Scanning program for peripheral usage...");
		monitor.checkCancelled();
		Map<SvdPeripheral, PeripheralUsage> peripheralUsage = findPeripheralUsage(device, monitor);
		
		// Extract only the peripherals that are actually used for segment creation
		Set<SvdPeripheral> usedPeripherals = new HashSet<>();
		for (PeripheralUsage usage : peripheralUsage.values()) {
			if (usage.isUsed) {
				usedPeripherals.add(usage.peripheral);
			}
		}
		
		monitor.setMessage("Creating blocks for " + usedPeripherals.size() + " used peripherals...");
		monitor.checkCancelled();
		Map<Block, BlockInfo> blocks = createBlocksFromUsedPeripherals(usedPeripherals);

		for (BlockInfo blockInfo : blocks.values()) {
			monitor.setMessage("Processing " + blockInfo.name + "...");
			monitor.checkCancelled();
			processBlock(blockInfo);
		}
		
		// Add SVD comments for all used peripherals (with full register data available) after all blocks are processed
		monitor.setMessage("Adding SVD comments to instructions...");
		monitor.checkCancelled();
		addSvdCommentsToInstructions(usedPeripherals);
		
		Msg.info(getClass(), "SVD import complete. Created " + blocks.size() + " memory blocks for " + 
				 usedPeripherals.size() + " used peripherals out of " + device.getPeripherals().size() + " total peripherals.");
	}

	/**
	 * Wrapper class to track peripheral usage while maintaining register data
	 */
	private static class PeripheralUsage {
		public final SvdPeripheral peripheral;
		public boolean isUsed;
		
		public PeripheralUsage(SvdPeripheral peripheral) {
			this.peripheral = peripheral;
			this.isUsed = false;
		}
	}

	/**
	 * Scan the program to find which peripherals are actually referenced in the code
	 * Returns a map of all peripherals with usage flags
	 */
	private Map<SvdPeripheral, PeripheralUsage> findPeripheralUsage(SvdDevice device, TaskMonitor monitor) throws CancelledException {
		// Create usage tracking for ALL peripherals (so derivedFrom works)
		Map<SvdPeripheral, PeripheralUsage> peripheralUsage = new HashMap<>();
		for (SvdPeripheral periph : device.getPeripherals()) {
			peripheralUsage.put(periph, new PeripheralUsage(periph));
		}
		
		Listing listing = mProgram.getListing();
		
		// Scan all instructions for memory references
		var instructionIterator = listing.getInstructions(true);
		int instructionsScanned = 0;
		
		while (instructionIterator.hasNext()) {
			monitor.checkCancelled();
			
			if (++instructionsScanned % 1000 == 0) {
				monitor.setMessage("Scanning instructions for peripheral usage... (" + instructionsScanned + " instructions)");
			}
			
			var instruction = instructionIterator.next();
			
			// Check each operand for memory references
			for (int i = 0; i < instruction.getNumOperands(); i++) {
				var operandAddresses = instruction.getOperandReferences(i);
				for (var ref : operandAddresses) {
					if (ref.isMemoryReference()) {
						long targetAddr = ref.getToAddress().getOffset();
						
						// Check if this address belongs to any peripheral
						SvdPeripheral matchingPeriph = findPeripheralForAddress(targetAddr, device.getPeripherals());
						if (matchingPeriph != null) {
							peripheralUsage.get(matchingPeriph).isUsed = true;
						}
					}
				}
			}
			
			// Also check immediate values that might be peripheral addresses
			for (int i = 0; i < instruction.getNumOperands(); i++) {
				Object[] opObjects = instruction.getOpObjects(i);
				for (Object obj : opObjects) {
					if (obj instanceof Number) {
						long value = ((Number) obj).longValue();
						SvdPeripheral matchingPeriph = findPeripheralForAddress(value, device.getPeripherals());
						if (matchingPeriph != null) {
							peripheralUsage.get(matchingPeriph).isUsed = true;
						}
					}
				}
			}
		}
		
		// Also scan data values that might contain peripheral addresses
		var dataIterator = listing.getDefinedData(true);
		int dataScanned = 0;
		
		while (dataIterator.hasNext()) {
			monitor.checkCancelled();
			
			if (++dataScanned % 1000 == 0) {
				monitor.setMessage("Scanning data for peripheral usage... (" + dataScanned + " data items)");
			}
			
			var data = dataIterator.next();
			
			// Check if data contains addresses that might reference peripherals
			if (data.hasStringValue()) {
				continue; // Skip string data
			}
			
			try {
				// Check scalar values
				if (data.getDataType().getLength() <= 8) { // 1, 2, 4, or 8 byte values
					Object value = data.getValue();
					if (value instanceof Number) {
						long addr = ((Number) value).longValue();
						SvdPeripheral matchingPeriph = findPeripheralForAddress(addr, device.getPeripherals());
						if (matchingPeriph != null) {
							peripheralUsage.get(matchingPeriph).isUsed = true;
						}
					}
				}
			} catch (Exception e) {
				// Ignore data that can't be interpreted as addresses
			}
		}
		
		// Count how many peripherals are marked as used
		long usedCount = peripheralUsage.values().stream().mapToLong(usage -> usage.isUsed ? 1 : 0).sum();
		monitor.setMessage("Found " + usedCount + " used peripherals out of " + device.getPeripherals().size() + " total");
		return peripheralUsage;
	}
	
	/**
	 * Find which peripheral contains the given address
	 */
	private SvdPeripheral findPeripheralForAddress(long address, List<SvdPeripheral> peripherals) {
		for (SvdPeripheral periph : peripherals) {
			// Check if address falls within any address block of this peripheral
			for (SvdAddressBlock block : periph.getAddressBlocks()) {
				long blockStart = periph.getBaseAddr() + block.getOffset();
				long blockEnd = blockStart + block.getSize() - 1;
				
				if (address >= blockStart && address <= blockEnd) {
					return periph;
				}
			}
			
			// Also check individual register addresses
			for (SvdRegister reg : periph.getRegisters()) {
				long regAddr = periph.getBaseAddr() + reg.getOffset();
				// Check if address is within register boundaries (assuming 32-bit registers)
				if (address >= regAddr && address < regAddr + Math.max(4, reg.getSize() / 8)) {
					return periph;
				}
			}
		}
		return null;
	}
	
	/**
	 * Create blocks only from peripherals that are actually used in the program
	 */
	private Map<Block, BlockInfo> createBlocksFromUsedPeripherals(Set<SvdPeripheral> usedPeripherals) {
		Map<Block, BlockInfo> blocks = new HashMap<Block, BlockInfo>();

		// Convert only used peripherals to blocks...
		for (SvdPeripheral periph : usedPeripherals) {
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
			// Note: SVD comments are now added after all blocks are processed
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
		for (SvdPeripheral periph : blockInfo.peripherals) {
			for (SvdRegister reg : periph.getRegisters()) {
				if (reg.getOffset() < blockInfo.block.getSize()) {
					// Choose the appropriate data type based on register size
					int regSizeBytes = reg.getSize() / 8;
					DataType dataType;
					switch (regSizeBytes) {
						case 1:
							dataType = new ByteDataType();
							break;
						case 2:
							dataType = new WordDataType();
							break;
						case 4:
							dataType = new DWordDataType();
							break;
						case 8:
							dataType = new QWordDataType();
							break;
						default:
							// For unusual sizes, create an array of bytes
							dataType = new ArrayDataType(new ByteDataType(), regSizeBytes, 1);
							break;
					}
					
					try {
						struct.replaceAtOffset(reg.getOffset(), dataType, 1, reg.getName(), reg.getDescription());
					} catch (Exception e) {
						// Log the error but continue processing other registers
						Msg.warn(getClass(), "Could not add register " + reg.getName() + " at offset 0x" + 
							String.format("%X", reg.getOffset()) + " to structure " + struct_name + ": " + e.getMessage());
					}
				}
			}
		}
		return struct;
	}
	
	/**
	 * Process instructions in the program and add SVD-based comments
	 * for memory references that match SVD registers from all used peripherals
	 */
	private void addSvdCommentsToInstructions(Set<SvdPeripheral> usedPeripherals) {
		Listing listing = mProgram.getListing();
		
		// Create a comprehensive map of register addresses to their information from ALL used peripherals
		Map<Long, String> registerMap = new HashMap<>();
		// Also create a map for peripheral base addresses (for peripherals with no detailed registers)
		Map<Long, String> peripheralBaseMap = new HashMap<>();
		
		for (SvdPeripheral periph : usedPeripherals) {
			Msg.info(getClass(), "Processing peripheral: " + periph.getName() + " at base 0x" + String.format("%08X", periph.getBaseAddr()) + " with " + periph.getRegisters().size() + " registers");
			
			// For peripherals with detailed registers, add each register
			if (periph.getRegisters().size() > 0) {
				for (SvdRegister reg : periph.getRegisters()) {
					long regAddress = periph.getBaseAddr() + reg.getOffset();
					
					// Debug RTC specifically
					if (periph.getName().equals("RTC")) {
						Msg.info(getClass(), "RTC Register: " + reg.getName() + " at offset 0x" + String.format("%X", reg.getOffset()) + " -> address 0x" + String.format("%08X", regAddress));
					}
					
					// Build comprehensive comment with peripheral and register info
					StringBuilder regInfo = new StringBuilder();
					
					// Start with peripheral.register name
					regInfo.append(periph.getName()).append(".").append(reg.getName());
					
					// Add peripheral description first (if available)
					String periphDesc = periph.getDescription();
					String regDesc = reg.getDescription();
					
					if (periphDesc != null && !periphDesc.trim().isEmpty() && 
						regDesc != null && !regDesc.trim().isEmpty()) {
						// Both descriptions available - format: "Peripheral Desc; Register Desc"
						regInfo.append(" - ").append(periphDesc.trim())
							   .append("; ").append(regDesc.trim());
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
					
					// Add field information with actual register value analysis
					if (!reg.getFields().isEmpty()) {
						String fieldAnalysis = analyzeRegisterFields(regAddress, reg);
						if (fieldAnalysis != null && !fieldAnalysis.trim().isEmpty()) {
							regInfo.append(" {").append(fieldAnalysis).append("}");
						}
					}
					
					// Add register offset information for reference
					long regOffset = reg.getOffset();
					regInfo.append(" @0x").append(String.format("%X", regOffset));
					
					registerMap.put(regAddress, regInfo.toString());
				}
			} else {
				// For peripherals with no detailed registers, add base address mapping
				Msg.info(getClass(), "Adding fallback mapping for " + periph.getName() + " (no detailed registers)");
				StringBuilder periphInfo = new StringBuilder();
				periphInfo.append(periph.getName()).append(" peripheral");
				
				// Add peripheral description if available
				String periphDesc = periph.getDescription();
				if (periphDesc != null && !periphDesc.trim().isEmpty()) {
					periphInfo.append(" - ").append(periphDesc.trim());
				}
				periphInfo.append(" @base");
				
				peripheralBaseMap.put(periph.getBaseAddr(), periphInfo.toString());
			}
		}
		
		if (registerMap.isEmpty() && peripheralBaseMap.isEmpty()) {
			Msg.info(getClass(), "No registers or peripheral bases found for comment creation");
			return; // No registers to process
		}
		
		Msg.info(getClass(), "Created register map with " + registerMap.size() + " registers and " + peripheralBaseMap.size() + " peripheral bases from " + usedPeripherals.size() + " peripherals");
		// Debug: Print first few register addresses
		int count = 0;
		for (Map.Entry<Long, String> entry : registerMap.entrySet()) {
			if (count++ < 5) {
				Msg.info(getClass(), "Register: 0x" + String.format("%08X", entry.getKey()) + " -> " + entry.getValue());
			}
		}
		// Debug: Print peripheral base addresses
		for (Map.Entry<Long, String> entry : peripheralBaseMap.entrySet()) {
			Msg.info(getClass(), "Peripheral base: 0x" + String.format("%08X", entry.getKey()) + " -> " + entry.getValue());
		}
		
		// Scan instructions and add SVD comments
		int transactionId = mProgram.startTransaction("SVD comment addition for all peripherals");
		boolean ok = false;
		int commentsAdded = 0;
		try {
			// Iterate through all instructions in the program
			var instructionIterator = listing.getInstructions(true);
			int instructionsProcessed = 0;
				
			while (instructionIterator.hasNext()) {
				var instruction = instructionIterator.next();
				instructionsProcessed++;
				
				// Check each operand for memory references
				for (int i = 0; i < instruction.getNumOperands(); i++) {
					var operandAddresses = instruction.getOperandReferences(i);
					for (var ref : operandAddresses) {
						if (ref.isMemoryReference()) {
							long targetAddr = ref.getToAddress().getOffset();
							
							// Debug: Log every memory reference we check
							if (instructionsProcessed <= 10) {
								Msg.info(getClass(), "Checking memory ref: 0x" + String.format("%08X", targetAddr) + " at instruction " + instruction.getAddress());
							}
							
							// Check if this address matches any SVD register
							String regInfo = findMatchingRegister(targetAddr, registerMap);
							if (regInfo == null) {
								// Check if it matches a peripheral base address
								regInfo = findMatchingPeripheralBase(targetAddr, peripheralBaseMap);
							}
							
							if (regInfo != null) {
								// Debug: Log when we find a match
								Msg.info(getClass(), "Found register/peripheral match: 0x" + String.format("%08X", targetAddr) + " -> " + regInfo + " at instruction " + instruction.getAddress());
								
								// Simply overwrite any existing comment with our SVD comment
								String newComment = "SVD: " + regInfo;
								listing.setComment(instruction.getAddress(), CodeUnit.EOL_COMMENT, newComment);
								commentsAdded++;
							}
						}
					}
				}
			}
			ok = true;
			Msg.info(getClass(), "Added " + commentsAdded + " SVD comments for all used peripherals");
		} catch (Exception e) {
			Msg.error(getClass(), "Error adding SVD comments for all peripherals", e);
		}
		mProgram.endTransaction(transactionId, ok);
	}
	
	/**
	 * Process instructions in the program and add SVD-based comments
	 * for memory references that match SVD registers (legacy method for single block)
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
				
				// Add peripheral description first (if available)
				String periphDesc = periph.getDescription();
				String regDesc = reg.getDescription();
				
				if (periphDesc != null && !periphDesc.trim().isEmpty() && 
					regDesc != null && !regDesc.trim().isEmpty()) {
					// Both descriptions available - format: "Peripheral Desc; Register Desc"
					regInfo.append(" - ").append(periphDesc.trim())
						   .append("; ").append(regDesc.trim());
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
								// Simply overwrite any existing comment with our SVD comment
								String newComment = "SVD: " + regInfo;
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
	 * Find a matching peripheral base for the given address
	 * This is used for peripherals that don't have detailed register definitions
	 */
	private String findMatchingPeripheralBase(long targetAddr, Map<Long, String> peripheralBaseMap) {
		// Check if target address is within a reasonable range of any peripheral base
		for (Map.Entry<Long, String> entry : peripheralBaseMap.entrySet()) {
			long baseAddr = entry.getKey();
			// Check if target address is within 1KB of peripheral base address
			// This is a reasonable assumption for most peripheral register spaces
			if (targetAddr >= baseAddr && targetAddr < baseAddr + 0x400) {
				String periphInfo = entry.getValue();
				long offset = targetAddr - baseAddr;
				if (offset > 0) {
					periphInfo += String.format(" +0x%X", offset);
				}
				return periphInfo;
			}
		}
		
		return null;
	}
	
	/**
	 * Analyze register fields with actual memory values from Ghidra
	 * @param regAddress The register address to read from
	 * @param register The SVD register with field definitions
	 * @return String containing field analysis, or null if no meaningful analysis
	 */
	private String analyzeRegisterFields(long regAddress, SvdRegister register) {
		try {
			// Try to read the actual register value from memory
			AddressSpace addrSpace = mProgram.getAddressFactory().getDefaultAddressSpace();
			Address addr = addrSpace.getAddress(regAddress);
			
			// Check if memory exists at this address
			MemoryBlock memBlock = mMemory.getBlock(addr);
			if (memBlock == null) {
				// No memory block - fall back to basic field listing
				return createBasicFieldListing(register);
			}
			
			// Read the register value based on register size
			long registerValue = 0;
			int regSizeBytes = register.getSize() / 8;
			
			try {
				switch (regSizeBytes) {
					case 1:
						registerValue = mMemory.getByte(addr) & 0xFF;
						break;
					case 2:
						registerValue = mMemory.getShort(addr) & 0xFFFF;
						break;
					case 4:
						registerValue = mMemory.getInt(addr) & 0xFFFFFFFFL;
						break;
					case 8:
						registerValue = mMemory.getLong(addr);
						break;
					default:
						// For unusual sizes, assume 4 bytes and try to read
						registerValue = mMemory.getInt(addr) & 0xFFFFFFFFL;
						break;
				}
				
				// Debug: Log successful memory read
				Msg.info(getClass(), "Successfully read register " + register.getName() + " at 0x" + 
					String.format("%08X", regAddress) + " = 0x" + String.format("%08X", registerValue));
				
			} catch (Exception e) {
				// Memory read failed - log the error and try to use 0 as default for peripheral registers
				Msg.info(getClass(), "Memory read failed for register " + register.getName() + " at 0x" + 
					String.format("%08X", regAddress) + ": " + e.getMessage() + " - using default value 0x0");
				registerValue = 0L; // Use 0 as default for peripheral registers
			}
			
			// Analyze each field with the actual register value - show ALL fields with their values
			StringBuilder fieldAnalysis = new StringBuilder();
			boolean first = true;
			
			for (var field : register.getFields()) {
				long fieldValue = field.extractValue(registerValue);
				
				if (!first) fieldAnalysis.append(", ");
				
				// Start with field name
				fieldAnalysis.append(field.getName()).append(":");
				
				// Check for enumerated value match first
				if (field.hasEnumeratedValues()) {
					SvdEnumeratedValue enumValue = field.findEnumeratedValue(fieldValue);
					if (enumValue != null) {
						// Format: FIELDNAME:ENUM_NAME - enum description (actual_value)
						fieldAnalysis.append(enumValue.getName());
						String enumDesc = enumValue.getDescription();
						if (enumDesc != null && !enumDesc.trim().isEmpty()) {
							fieldAnalysis.append(" - ").append(enumDesc.trim());
						}
						fieldAnalysis.append(" (").append(fieldValue).append(")");
					} else {
						// Field has enumerated values but current value doesn't match any
						// Format: FIELDNAME:Unknown enum value (actual_value)
						String desc = field.getDescription();
						if (desc != null && !desc.trim().isEmpty()) {
							fieldAnalysis.append(desc.trim()).append(" - ");
						}
						fieldAnalysis.append("Unknown enum value (").append(fieldValue).append(")");
					}
				} else {
					// No enumerated values - format: FIELDNAME:Description (actual_value)
					String desc = field.getDescription();
					if (desc != null && !desc.trim().isEmpty()) {
						fieldAnalysis.append(desc.trim());
					} else {
						fieldAnalysis.append("Field");
					}
					fieldAnalysis.append(" (").append(fieldValue).append(")");
				}
				
				first = false;
			}
			
			return fieldAnalysis.toString();
			
		} catch (Exception e) {
			// Any error - fall back to basic field listing
			return createBasicFieldListing(register);
		}
	}
	
	/**
	 * Create a basic field listing without value analysis
	 * @param register The SVD register with field definitions
	 * @return String containing basic field names and descriptions
	 */
	private String createBasicFieldListing(SvdRegister register) {
		StringBuilder fieldInfo = new StringBuilder();
		boolean first = true;
		
		for (var field : register.getFields()) {
			if (!first) fieldInfo.append(", ");
			fieldInfo.append(field.getName());
			
			// Show enumerated values if available (abbreviated)
			if (field.hasEnumeratedValues()) {
				fieldInfo.append("[");
				boolean firstEnum = true;
				int enumCount = 0;
				for (var enumValue : field.getEnumeratedValues()) {
					if (enumCount >= 3) { // Limit to first 3 enum values
						fieldInfo.append("...");
						break;
					}
					if (!firstEnum) fieldInfo.append("|");
					fieldInfo.append(enumValue.getName());
					firstEnum = false;
					enumCount++;
				}
				fieldInfo.append("]");
			} else {
				// Add concise description if available and no enumerated values
				String desc = field.getDescription();
				if (desc != null && !desc.trim().isEmpty() && desc.length() < 50) {
					fieldInfo.append(":").append(desc.trim());
				}
			}
			first = false;
		}
		
		return fieldInfo.toString();
	}
	
}
