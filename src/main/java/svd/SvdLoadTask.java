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
import java.util.ArrayList;
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
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
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
import io.svdparser.SvdInterrupt;
import io.svdparser.SvdParserException;
import io.svdparser.SvdPeripheral;
import io.svdparser.SvdRegister;
import svd.MemoryUtils.MemRangeRelation;

public class SvdLoadTask extends Task {
	
	// Constants for SVD comment format
	private static final String SVD_COMMENT_PREFIX = "SVD: ";
	private static final String PIPE_SEPARATOR = "|";
	private static final String COMMA_SEPARATOR = ",";
	private static final String COLON_SEPARATOR = ":";
	private static final String NOT_AVAILABLE = "N/A";
	
	// Constants for operations
	private static final String OPERATION_READ = "READ";
	private static final String OPERATION_WRITE = "WRITE";
	private static final String OPERATION_WRITE_UNKNOWN = "WRITE:UNKNOWN";
	
	// Constants for interrupt actions
	private static final String INTERRUPT_ACTION_ENABLE = "ENABLE";
	private static final String INTERRUPT_ACTION_DISABLE = "DISABLE";
	private static final String INTERRUPT_ACTION_STATUS = "STATUS";
	
	// Constants for register patterns
	private static final String[] CONTROL_REGISTER_NAMES = {"CTRL", "CTRLA", "CTRLB"};
	private static final String[] INTERRUPT_REGISTER_PATTERNS = {"INTEN", "IRQ", "INT", "MASK", "ENABLE", "FLAG", "STATUS", "CTRL"};
	private static final String[] ENABLE_REGISTER_PATTERNS = {"INTENSET", "ENABLE"};
	private static final String[] DISABLE_REGISTER_PATTERNS = {"INTENCLR", "DISABLE"};
	
	private static final int DEFAULT_REGISTER_SIZE = 32;
	private static final int MAX_INTERRUPTS_IN_COMMENT = 3;
	private static final int REGISTER_LOOKBACK_LIMIT = 5;
	
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
			Msg.error(getClass(), "Memory conflict while creating block " + blockInfo.name + 
				" at address 0x" + String.format("%08X", blockInfo.block.getAddress()), e);
		} catch (IllegalArgumentException e) {
			Msg.error(getClass(), "Invalid argument while creating block " + blockInfo.name, e);
		} catch (AddressOverflowException e) {
			Msg.error(getClass(), "Address overflow while creating block " + blockInfo.name + 
				" at address 0x" + String.format("%08X", blockInfo.block.getAddress()), e);
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
				Msg.error(getClass(), "Error renaming memory block " + collidingMemoryBlock.getName() + 
					" to " + blockInfo.name, e);
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
			Msg.error(getClass(), "Invalid input while creating symbol for block " + blockInfo.name + 
				" at address 0x" + String.format("%08X", blockInfo.block.getAddress()), e);
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
			Msg.error(getClass(), "Error creating namespace '" + name + "'", e);
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
			Msg.error(getClass(), "Error adding data type for block " + blockInfo.name, e);
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
			// For peripherals with detailed registers, add each register
			if (periph.getRegisters().size() > 0) {
				for (SvdRegister reg : periph.getRegisters()) {
					long regAddress = periph.getBaseAddr() + reg.getOffset();
					
					// Build comprehensive comment with peripheral and register info
					StringBuilder regInfo = new StringBuilder();
					
					// Start with peripheral.register name, using cluster format if applicable
					if (reg.isClusterRegister()) {
						// Format: PERIPHERAL[ACTIVE_MODE].REGISTER (determine active mode dynamically)
						String registerName = reg.getName();
						String clusterPrefix = reg.getClusterName() + "_";
						if (registerName.startsWith(clusterPrefix)) {
							registerName = registerName.substring(clusterPrefix.length());
						}
						
						// Determine the active cluster mode based on MODE field value
						String activeMode = determineActiveClusterMode(periph, usedPeripherals);
						String displayMode = (activeMode != null) ? activeMode : reg.getClusterName();
						
						regInfo.append(periph.getName()).append("[").append(displayMode).append("].").append(registerName);
					} else {
						// Format: PERIPHERAL.REGISTER
						regInfo.append(periph.getName()).append(".").append(reg.getName());
					}
					
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
			return; // No registers to process
		}
		
		// Scan instructions and add SVD comments
		int transactionId = mProgram.startTransaction("SVD comment addition for all peripherals");
		boolean ok = false;
		int commentsAdded = 0;
		try {
			// Iterate through all instructions in the program
			var instructionIterator = listing.getInstructions(true);
				
			while (instructionIterator.hasNext()) {
				var instruction = instructionIterator.next();
				
				// Check each operand for memory references
				for (int i = 0; i < instruction.getNumOperands(); i++) {
					var operandAddresses = instruction.getOperandReferences(i);
					for (var ref : operandAddresses) {
						if (ref.isMemoryReference()) {
							long targetAddr = ref.getToAddress().getOffset();
							
							// Check if this address matches any SVD register
							String regInfo = findMatchingRegister(targetAddr, registerMap);
							if (regInfo == null) {
								// Check if it matches a peripheral base address
								regInfo = findMatchingPeripheralBase(targetAddr, peripheralBaseMap);
							}
							
							if (regInfo != null) {
								// Determine operation type and generate new pipe-delimited format
								boolean isWriteOperation = isWriteOperationToPeripheral(instruction, targetAddr);
								
								// Extract immediate value for write operations
								Long immediateValue = null;
								if (isWriteOperation) {
									immediateValue = extractImmediateValueForWrite(instruction, targetAddr);
								}
								
								// Generate new pipe-delimited format
								String newFormatComment = generateNewSvdComment(targetAddr, immediateValue, usedPeripherals, isWriteOperation);
								
								if (newFormatComment != null) {
									// Use new pipe-delimited format
									String newComment = "SVD: " + newFormatComment;
									listing.setComment(instruction.getAddress(), CodeUnit.EOL_COMMENT, newComment);
									commentsAdded++;
								}
							}
						}
					}
				}
			}
			ok = true;
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
				
			} catch (Exception e) {
				// Memory read failed - use 0 as default for peripheral registers
				registerValue = 0L;
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
						fieldAnalysis.append(" (0x").append(Long.toHexString(fieldValue).toUpperCase()).append(")");
					} else {
						// Field has enumerated values but current value doesn't match any
						// Format: FIELDNAME:Unknown enum value (actual_value)
						String desc = field.getDescription();
						if (desc != null && !desc.trim().isEmpty()) {
							fieldAnalysis.append(desc.trim()).append(" - ");
						}
						fieldAnalysis.append("Unknown enum value (0x").append(Long.toHexString(fieldValue).toUpperCase()).append(")");
					}
				} else {
					// No enumerated values - format: FIELDNAME:Description (actual_value)
					String desc = field.getDescription();
					if (desc != null && !desc.trim().isEmpty()) {
						fieldAnalysis.append(desc.trim());
					} else {
						fieldAnalysis.append("Field");
					}
					fieldAnalysis.append(" (0x").append(Long.toHexString(fieldValue).toUpperCase()).append(")");
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
	
	/**
	 * Extract immediate value from write instructions to peripheral registers
	 * @param instruction The instruction to analyze
	 * @param targetAddr The target register address being written to
	 * @return The immediate value being written, or null if not a write with immediate value
	 */
	private Long extractImmediateValueForWrite(Instruction instruction, long targetAddr) {
		try {
			String mnemonic = instruction.getMnemonicString().toLowerCase();
			
			// Check for write operations (store instructions)
			if (mnemonic.startsWith("str") || mnemonic.startsWith("strh") || mnemonic.startsWith("strb")) {
				// For store instructions, get the source operand (what's being stored)
				if (instruction.getNumOperands() >= 2) {
					Object sourceOperand = instruction.getOpObjects(0)[0]; // First operand is source register
					
					// Try to get the scalar value if it's an immediate or known register value
					if (sourceOperand instanceof Scalar) {
						return ((Scalar) sourceOperand).getValue();
					}
					
					// For register operands, try to trace back to find immediate values
					// This handles cases like: mov r2, #0x10000; str r2, [r3, #0x4]
					return traceRegisterToImmediate(instruction, sourceOperand);
				}
			}
			
			// Check for immediate arithmetic operations on memory (like orr with immediate)
			if (mnemonic.equals("orr") || mnemonic.equals("bic") || mnemonic.equals("and") || mnemonic.equals("eor")) {
				// Check if this is a read-modify-write operation on our target address
				if (instruction.getNumOperands() >= 3) {
					Object immOperand = instruction.getOpObjects(2)[0]; // Third operand is usually immediate
					if (immOperand instanceof Scalar) {
						return ((Scalar) immOperand).getValue();
					}
				}
			}
			
			return null;
		} catch (Exception e) {
			return null;
		}
	}
	
	/**
	 * Trace a register back to find its immediate value from recent instructions
	 * @param currentInstruction The current instruction
	 * @param registerOperand The register operand to trace
	 * @return The immediate value loaded into the register, or null if not found
	 */
	private Long traceRegisterToImmediate(Instruction currentInstruction, Object registerOperand) {
		try {
			if (!(registerOperand instanceof Register)) {
				return null;
			}
			
			Register targetRegister = (Register) registerOperand;
			Listing listing = mProgram.getListing();
			
			// Look backwards through a few instructions to find immediate loads
			Instruction prevInstruction = listing.getInstructionBefore(currentInstruction.getAddress());
			int lookbackLimit = 5; // Don't look too far back
			
			while (prevInstruction != null && lookbackLimit > 0) {
				String prevMnemonic = prevInstruction.getMnemonicString().toLowerCase();
				
				// Check for immediate load instructions (mov, movw, mov.w)
				if ((prevMnemonic.equals("mov") || prevMnemonic.equals("movw") || prevMnemonic.equals("mov.w")) && 
					prevInstruction.getNumOperands() >= 2) {
					
					// Check if destination register matches our target
					Object destOperand = prevInstruction.getOpObjects(0)[0];
					if (destOperand instanceof Register && destOperand.equals(targetRegister)) {
						// Get the immediate value
						Object srcOperand = prevInstruction.getOpObjects(1)[0];
						if (srcOperand instanceof Scalar) {
							return ((Scalar) srcOperand).getValue();
						}
					}
				}
				
				// Check for memory load instructions (ldr)
				if (prevMnemonic.equals("ldr") && prevInstruction.getNumOperands() >= 2) {
					// Check if destination register matches our target
					Object destOperand = prevInstruction.getOpObjects(0)[0];
					if (destOperand instanceof Register && destOperand.equals(targetRegister)) {
						// Get the memory address being loaded from
						try {
							// Check if this is a memory reference in the operand
							var operandRefs = prevInstruction.getOperandReferences(1);
							for (var ref : operandRefs) {
								if (ref.isMemoryReference()) {
									long memAddr = ref.getToAddress().getOffset();
									// Try to read the value from that memory address
									Long memValue = readValueFromMemory(memAddr);
									if (memValue != null) {
										return memValue;
									}
								}
							}
						} catch (Exception e) {
							// Continue to next instruction if memory read fails
						}
					}
				}
				
				// Check for arithmetic operations that modify the register (orr, bic, and, eor)
				if ((prevMnemonic.equals("orr") || prevMnemonic.equals("bic") || prevMnemonic.equals("and") || prevMnemonic.equals("eor")) && 
					prevInstruction.getNumOperands() >= 3) {
					
					// Check if destination register matches our target
					Object destOperand = prevInstruction.getOpObjects(0)[0];
					if (destOperand instanceof Register && destOperand.equals(targetRegister)) {
						// Get the immediate value used in the operation
						Object immOperand = prevInstruction.getOpObjects(2)[0]; // Third operand is usually immediate
						if (immOperand instanceof Scalar) {
							// For read-modify-write operations, return the immediate value being applied
							// This represents what's being ORed/cleared/etc.
							return ((Scalar) immOperand).getValue();
						}
					}
				}
				
				// Also check for load immediate high (movt) instructions
				if (prevMnemonic.equals("movt") && prevInstruction.getNumOperands() >= 2) {
					Object destOperand = prevInstruction.getOpObjects(0)[0];
					if (destOperand instanceof Register && destOperand.equals(targetRegister)) {
						// For movt, we'd need to combine with previous movw, but for now just return what we can
						Object srcOperand = prevInstruction.getOpObjects(1)[0];
						if (srcOperand instanceof Scalar) {
							return ((Scalar) srcOperand).getValue() << 16; // High 16 bits
						}
					}
				}
				
				prevInstruction = listing.getInstructionBefore(prevInstruction.getAddress());
				lookbackLimit--;
			}
			
			return null;
		} catch (Exception e) {
			return null;
		}
	}
	
	/**
	 * Generate new pipe-delimited SVD comment format
	 * @param targetAddr The target register address
	 * @param immediateValue The immediate value being written (null for reads)
	 * @param usedPeripherals Set of used peripherals to search for the register
	 * @param isWrite True if this is a write operation
	 * @return New pipe-delimited SVD comment format
	 */
	private String generateNewSvdComment(long targetAddr, Long immediateValue, Set<SvdPeripheral> usedPeripherals, boolean isWrite) {
		try {
			// Find the register object and peripheral for this address
			SvdRegister register = findRegisterByAddress(targetAddr, usedPeripherals);
			SvdPeripheral peripheral = findPeripheralByAddress(targetAddr, usedPeripherals);
			
			if (register == null || peripheral == null) {
				return buildFallbackComment(isWrite, "UNKNOWN.REGISTER");
			}
			
			// Build all components for the pipe-delimited format
			String regPath = buildRegisterPath(peripheral, register, immediateValue);
			String peripheralDesc = getDescriptionOrDefault(peripheral.getDescription());
			String clusterDesc = buildClusterDescription(register, peripheral, immediateValue, null);
			String registerDesc = getDescriptionOrDefault(register.getDescription());
			String size = buildSizeString(register);
			String operation = buildOperationString(isWrite, immediateValue);
			String fields = buildFieldsString(register, immediateValue);
			String interrupts = buildInterruptsString(targetAddr, immediateValue, usedPeripherals);
			String modeContext = buildModeContextString(register, peripheral, immediateValue);
			
			// Construct final pipe-delimited format
			return String.join(PIPE_SEPARATOR, regPath, peripheralDesc, clusterDesc, 
				registerDesc, size, operation, fields, interrupts, modeContext);
			
		} catch (Exception e) {
			// Log error with context for debugging
			Msg.warn(getClass(), "Error generating SVD comment for address 0x" + 
				Long.toHexString(targetAddr).toUpperCase() + ": " + e.getMessage(), e);
			return buildFallbackComment(isWrite, "ERROR.REGISTER");
		}
	}
	
	/**
	 * Build register path component: PERIPHERAL[CLUSTER].REGISTER
	 */
	private String buildRegisterPath(SvdPeripheral peripheral, SvdRegister register, Long immediateValue) {
		StringBuilder regPath = new StringBuilder();
		regPath.append(peripheral.getName());
		
		if (register.isClusterRegister()) {
			// For cluster registers, try to determine active mode
			var modeInfo = determineClusterModeInfoFromImmediateValue(peripheral, register, immediateValue);
			String clusterName = (modeInfo != null) ? modeInfo.name : register.getClusterName();
			regPath.append("[").append(clusterName).append("]");
		}
		
		// Clean register name (remove cluster prefix if present)
		String registerName = cleanRegisterName(register);
		regPath.append(".").append(registerName);
		return regPath.toString();
	}
	
	/**
	 * Clean register name by removing cluster prefix if present
	 */
	private String cleanRegisterName(SvdRegister register) {
		String registerName = register.getName();
		if (register.isClusterRegister()) {
			String clusterPrefix = register.getClusterName() + "_";
			if (registerName.startsWith(clusterPrefix)) {
				registerName = registerName.substring(clusterPrefix.length());
			}
		}
		return registerName;
	}
	
	/**
	 * Build register size string
	 */
	private String buildSizeString(SvdRegister register) {
		return String.valueOf(register.getSize() > 0 ? register.getSize() : DEFAULT_REGISTER_SIZE);
	}
	
	/**
	 * Build fields string with proper fallback
	 */
	private String buildFieldsString(SvdRegister register, Long immediateValue) {
		String fields = generateFieldsAnalysis(register, immediateValue);
		return (fields != null && !fields.trim().isEmpty()) ? fields : NOT_AVAILABLE;
	}
	
	/**
	 * Build interrupts string with proper fallback
	 */
	private String buildInterruptsString(long targetAddr, Long immediateValue, Set<SvdPeripheral> usedPeripherals) {
		String interrupts = generateInterruptContext(targetAddr, immediateValue, usedPeripherals);
		return (interrupts != null && !interrupts.trim().isEmpty()) ? interrupts : NOT_AVAILABLE;
	}
	
	/**
	 * Build mode context string
	 */
	private String buildModeContextString(SvdRegister register, SvdPeripheral peripheral, Long immediateValue) {
		if (!register.isClusterRegister()) {
			return NOT_AVAILABLE;
		}
		
		var modeInfo = determineClusterModeInfoFromImmediateValue(peripheral, register, immediateValue);
		if (modeInfo != null && modeInfo.description != null && !modeInfo.description.trim().isEmpty()) {
			return modeInfo.description.trim();
		}
		return NOT_AVAILABLE;
	}
	
	/**
	 * Build fallback comment for error cases
	 */
	private String buildFallbackComment(boolean isWrite, String registerName) {
		String operation = isWrite ? OPERATION_WRITE : OPERATION_READ;
		return String.join(PIPE_SEPARATOR, registerName, NOT_AVAILABLE, NOT_AVAILABLE, 
			NOT_AVAILABLE, String.valueOf(DEFAULT_REGISTER_SIZE), operation, 
			NOT_AVAILABLE, NOT_AVAILABLE, NOT_AVAILABLE);
	}
	
	/**
	 * Build analysis string for a single field
	 */
	private String buildSingleFieldAnalysis(io.svdparser.SvdField field, Long registerValue) {
		StringBuilder fieldAnalysis = new StringBuilder();
		
		// Field name
		fieldAnalysis.append(field.getName()).append(COLON_SEPARATOR);
		
		// Bit offset
		fieldAnalysis.append(field.getBitOffset()).append(COLON_SEPARATOR);
		
		// Bit width and value
		fieldAnalysis.append(field.getBitWidth()).append("(");
		String fieldValueStr = buildFieldValueString(field, registerValue);
		fieldAnalysis.append(fieldValueStr).append(")").append(COLON_SEPARATOR);
		
		// Field description
		String fieldDesc = getDescriptionOrDefault(field.getDescription());
		if (fieldDesc.equals(NOT_AVAILABLE)) {
			fieldDesc = "Field";
		}
		fieldAnalysis.append(fieldDesc);
		
		// Enumerated value description (if applicable and value is known)
		String enumDesc = buildEnumeratedValueDescription(field, registerValue);
		if (enumDesc != null) {
			fieldAnalysis.append(COLON_SEPARATOR).append(enumDesc);
		}
		
		return fieldAnalysis.toString();
	}
	
	/**
	 * Build field value string
	 */
	private String buildFieldValueString(io.svdparser.SvdField field, Long registerValue) {
		if (registerValue != null) {
			long fieldValue = field.extractValue(registerValue);
			return "0x" + Long.toHexString(fieldValue).toUpperCase();
		}
		return "0x0"; // Default when value unknown
	}
	
	/**
	 * Build enumerated value description if applicable
	 */
	private String buildEnumeratedValueDescription(io.svdparser.SvdField field, Long registerValue) {
		if (registerValue == null || !field.hasEnumeratedValues()) {
			return null;
		}
		
		long fieldValue = field.extractValue(registerValue);
		SvdEnumeratedValue enumValue = field.findEnumeratedValue(fieldValue);
		if (enumValue != null) {
			String enumDesc = enumValue.getDescription();
			if (enumDesc != null && !enumDesc.trim().isEmpty()) {
				return enumDesc.trim();
			}
		}
		return null;
	}
	
	/**
	 * Check if we have valid context for interrupt analysis
	 */
	private boolean isValidInterruptContext(SvdPeripheral peripheral, SvdRegister register, Long immediateValue) {
		if (peripheral == null || register == null || peripheral.getInterrupts().isEmpty() || immediateValue == null) {
			return false;
		}
		
		// Check if this register name suggests it's interrupt-related
		String regName = register.getName().toUpperCase();
		for (String pattern : INTERRUPT_REGISTER_PATTERNS) {
			if (regName.contains(pattern)) {
				return true;
			}
		}
		return false;
	}
	
	/**
	 * Determine interrupt action based on register name
	 */
	private String determineInterruptAction(String registerName) {
		String regName = registerName.toUpperCase();
		
		for (String pattern : ENABLE_REGISTER_PATTERNS) {
			if (regName.contains(pattern)) {
				return INTERRUPT_ACTION_ENABLE;
			}
		}
		
		for (String pattern : DISABLE_REGISTER_PATTERNS) {
			if (regName.contains(pattern)) {
				return INTERRUPT_ACTION_DISABLE;
			}
		}
		
		return INTERRUPT_ACTION_STATUS;
	}
	
	/**
	 * Find interrupts affected by the immediate value
	 */
	private List<String> findAffectedInterrupts(SvdPeripheral peripheral, Long immediateValue, String action) {
		List<String> affectedInterrupts = new ArrayList<>();
		
		// Check each bit in the immediate value
		for (int bit = 0; bit < 32; bit++) {
			if ((immediateValue & (1L << bit)) != 0) {
				// This bit is set, find corresponding interrupt
				for (SvdInterrupt interrupt : peripheral.getInterrupts()) {
					if (interrupt.matchesBitPosition(bit)) {
						// Format: ACTION:INTERRUPT_NAME:VECTOR_NUMBER
						String interruptEntry = String.join(COLON_SEPARATOR, 
							action, interrupt.getName(), String.valueOf(interrupt.getValue()));
						affectedInterrupts.add(interruptEntry);
						break;
					}
				}
			}
		}
		
		return affectedInterrupts;
	}
	
	/**
	 * Get description or return "N/A" if null/empty
	 */
	private String getDescriptionOrDefault(String description) {
		return (description != null && !description.trim().isEmpty()) ? description.trim() : NOT_AVAILABLE;
	}
	
	/**
	 * Build cluster description component
	 */
	private String buildClusterDescription(SvdRegister register, SvdPeripheral peripheral, Long immediateValue, String activeClusterMode) {
		if (!register.isClusterRegister()) {
			return NOT_AVAILABLE;
		}
		
		var modeInfo = determineClusterModeInfoFromImmediateValue(peripheral, register, immediateValue);
		if (modeInfo != null && modeInfo.description != null && !modeInfo.description.trim().isEmpty()) {
			return modeInfo.description.trim();
		}
		
		return NOT_AVAILABLE;
	}
	
	/**
	 * Build operation string component
	 */
	private String buildOperationString(boolean isWrite, Long immediateValue) {
		if (!isWrite) {
			return OPERATION_READ;
		}
		
		if (immediateValue != null) {
			return OPERATION_WRITE + COLON_SEPARATOR + "0x" + Long.toHexString(immediateValue).toUpperCase();
		}
		
		return OPERATION_WRITE_UNKNOWN;
	}
	
	/**
	 * Generate fields analysis in new format: FIELD_NAME:OFFSET:WIDTH(VALUE):FIELD_DESCRIPTION:ENUMERATED_VALUE_DESCRIPTION
	 * @param register The register containing the fields
	 * @param registerValue The register value to analyze (null for unknown value)
	 * @return Comma-separated field analysis in new format
	 */
	private String generateFieldsAnalysis(SvdRegister register, Long registerValue) {
		if (register == null || register.getFields().isEmpty()) {
			return null;
		}
		
		List<String> fieldStrings = new ArrayList<>();
		for (var field : register.getFields()) {
			String fieldString = buildSingleFieldAnalysis(field, registerValue);
			fieldStrings.add(fieldString);
		}
		
		return String.join(COMMA_SEPARATOR, fieldStrings);
	}
	
	/**
	 * Generate interrupt context in new format: ACTION:INTERRUPT_NAME:VECTOR_NUMBER
	 * @param targetAddr The target register address
	 * @param immediateValue The immediate value being written (null for reads)
	 * @param usedPeripherals Set of used peripherals to search
	 * @return Comma-separated interrupt context in new format
	 */
	private String generateInterruptContext(long targetAddr, Long immediateValue, Set<SvdPeripheral> usedPeripherals) {
		try {
			// Find the peripheral and register for this address
			SvdPeripheral peripheral = findPeripheralByAddress(targetAddr, usedPeripherals);
			SvdRegister register = findRegisterByAddress(targetAddr, usedPeripherals);
			
			if (!isValidInterruptContext(peripheral, register, immediateValue)) {
				return null;
			}
			
			// Determine interrupt action based on register name
			String action = determineInterruptAction(register.getName());
			
			// Find affected interrupts
			List<String> affectedInterrupts = findAffectedInterrupts(peripheral, immediateValue, action);
			
			if (affectedInterrupts.isEmpty()) {
				return null;
			}
			
			// Limit to first 3 to avoid overly long comments
			return String.join(COMMA_SEPARATOR, 
				affectedInterrupts.subList(0, Math.min(affectedInterrupts.size(), MAX_INTERRUPTS_IN_COMMENT)));
			
		} catch (Exception e) {
			// Log error for debugging but don't fail SVD comment generation
			Msg.debug(getClass(), "Error generating interrupt context for address 0x" + 
				Long.toHexString(targetAddr).toUpperCase() + ": " + e.getMessage());
			return null;
		}
	}
	
	/**
	 * Find the SvdRegister object by its address
	 * @param targetAddr The register address to find
	 * @param usedPeripherals Set of used peripherals to search
	 * @return The SvdRegister object, or null if not found
	 */
	private SvdRegister findRegisterByAddress(long targetAddr, Set<SvdPeripheral> usedPeripherals) {
		// Search through the used peripherals to find the register
		try {
			for (SvdPeripheral periph : usedPeripherals) {
				for (SvdRegister reg : periph.getRegisters()) {
					long regAddress = periph.getBaseAddr() + reg.getOffset();
					if (regAddress == targetAddr) {
						return reg;
					}
				}
			}
		} catch (Exception e) {
			// Log error for debugging but don't fail the operation
			Msg.debug(getClass(), "Error finding register by address 0x" + 
				Long.toHexString(targetAddr).toUpperCase() + ": " + e.getMessage());
		}
		return null;
	}
	
	/**
	 * Find the SvdPeripheral object by register address
	 * @param targetAddr The register address to find
	 * @param usedPeripherals Set of used peripherals to search
	 * @return The SvdPeripheral object, or null if not found
	 */
	private SvdPeripheral findPeripheralByAddress(long targetAddr, Set<SvdPeripheral> usedPeripherals) {
		try {
			for (SvdPeripheral periph : usedPeripherals) {
				for (SvdRegister reg : periph.getRegisters()) {
					long regAddress = periph.getBaseAddr() + reg.getOffset();
					if (regAddress == targetAddr) {
						return periph;
					}
				}
			}
		} catch (Exception e) {
			// Log error for debugging but don't fail the operation
			Msg.debug(getClass(), "Error finding peripheral by address 0x" + 
				Long.toHexString(targetAddr).toUpperCase() + ": " + e.getMessage());
		}
		return null;
	}
	
	/**
	 * Create field analysis using a specific register value (for immediate value analysis)
	 * @param registerValue The register value to analyze
	 * @param register The SVD register with field definitions
	 * @return String containing field analysis
	 */
	private String analyzeRegisterFieldsWithValue(long registerValue, SvdRegister register) {
		// This is the same logic as in analyzeRegisterFields but using the provided value
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
					fieldAnalysis.append(" (0x").append(Long.toHexString(fieldValue).toUpperCase()).append(")");
				} else {
					// Field has enumerated values but current value doesn't match any
					String desc = field.getDescription();
					if (desc != null && !desc.trim().isEmpty()) {
						fieldAnalysis.append(desc.trim()).append(" - ");
					}
					fieldAnalysis.append("Unknown enum value (0x").append(Long.toHexString(fieldValue).toUpperCase()).append(")");
				}
			} else {
				// No enumerated values - format: FIELDNAME:Description (actual_value)
				String desc = field.getDescription();
				if (desc != null && !desc.trim().isEmpty()) {
					fieldAnalysis.append(desc.trim());
				} else {
					fieldAnalysis.append("Field");
				}
				fieldAnalysis.append(" (0x").append(Long.toHexString(fieldValue).toUpperCase()).append(")");
			}
			
			first = false;
		}
		
		return fieldAnalysis.toString();
	}
	
	/**
	 * Read a value from memory at the specified address
	 * @param memAddr The memory address to read from
	 * @return The value at that address, or null if read fails
	 */
	private Long readValueFromMemory(long memAddr) {
		try {
			AddressSpace addrSpace = mProgram.getAddressFactory().getDefaultAddressSpace();
			Address addr = addrSpace.getAddress(memAddr);
			
			// Check if memory exists at this address
			MemoryBlock memBlock = mMemory.getBlock(addr);
			if (memBlock == null) {
				return null;
			}
			
			// Try to read different sizes, starting with 4 bytes (most common)
			try {
				// Try 32-bit read first
				int value32 = mMemory.getInt(addr);
				return (long) value32 & 0xFFFFFFFFL;
			} catch (Exception e) {
				try {
					// Try 16-bit read
					short value16 = mMemory.getShort(addr);
					return (long) value16 & 0xFFFFL;
				} catch (Exception e2) {
					try {
						// Try 8-bit read
						byte value8 = mMemory.getByte(addr);
						return (long) value8 & 0xFFL;
					} catch (Exception e3) {
						return null;
					}
				}
			}
		} catch (Exception e) {
			return null;
		}
	}
	
	/**
	 * Determine if an instruction is writing to a peripheral register
	 * @param instruction The instruction to analyze
	 * @param targetAddr The peripheral register address
	 * @return True if this is a write operation, false if it's a read operation
	 */
	private boolean isWriteOperationToPeripheral(Instruction instruction, long targetAddr) {
		try {
			String mnemonic = instruction.getMnemonicString().toLowerCase();
			
			// Check for store (write) instructions
			if (mnemonic.startsWith("str")) { // str, strh, strb
				// For store instructions, check if the target address is in the destination operand
				// Format: str rX, [destination]
				if (instruction.getNumOperands() >= 2) {
					var destOperandRefs = instruction.getOperandReferences(1); // Second operand is destination
					for (var ref : destOperandRefs) {
						if (ref.isMemoryReference() && ref.getToAddress().getOffset() == targetAddr) {
							return true; // This is a write to our target address
						}
					}
				}
			}
			
			// Check for load (read) instructions
			if (mnemonic.startsWith("ldr")) { // ldr, ldrh, ldrb
				// For load instructions, check if the target address is in the source operand
				// Format: ldr rX, [source]
				if (instruction.getNumOperands() >= 2) {
					var srcOperandRefs = instruction.getOperandReferences(1); // Second operand is source
					for (var ref : srcOperandRefs) {
						if (ref.isMemoryReference() && ref.getToAddress().getOffset() == targetAddr) {
							return false; // This is a read from our target address
						}
					}
				}
			}
			
			// Default to read operation if we can't determine
			return false;
		} catch (Exception e) {
			// Default to read operation on error
			return false;
		}
	}
	
	/**
	 * Analyze interrupt context for interrupt-related register writes
	 * @param targetAddr The register address being written to
	 * @param immediateValue The value being written
	 * @param usedPeripherals Set of used peripherals to search
	 * @return Interrupt context string, or null if not interrupt-related
	 */
	private String analyzeInterruptContext(long targetAddr, Long immediateValue, Set<SvdPeripheral> usedPeripherals) {
		try {
			// Find the peripheral and register for this address
			SvdPeripheral peripheral = null;
			SvdRegister register = null;
			
			for (SvdPeripheral periph : usedPeripherals) {
				for (SvdRegister reg : periph.getRegisters()) {
					long regAddress = periph.getBaseAddr() + reg.getOffset();
					if (regAddress == targetAddr) {
						peripheral = periph;
						register = reg;
						break;
					}
				}
				if (peripheral != null) break;
			}
			
			if (peripheral == null || register == null || peripheral.getInterrupts().isEmpty()) {
				return null;
			}
			
			// Check if this register name suggests it's interrupt-related
			String regName = register.getName().toUpperCase();
			boolean isInterruptRegister = regName.contains("INTEN") || regName.contains("IRQ") || 
										 regName.contains("INT") || regName.contains("MASK") ||
										 regName.contains("ENABLE") || regName.contains("FLAG") ||
										 regName.contains("STATUS") || regName.contains("CTRL");
			
			
			if (!isInterruptRegister) {
				return null;
			}
			
			// Analyze which interrupts are affected by the immediate value
			List<String> affectedInterrupts = new ArrayList<>();
			
			// Check each bit in the immediate value
			for (int bit = 0; bit < 32; bit++) {
				if ((immediateValue & (1L << bit)) != 0) {
					// This bit is set, find corresponding interrupt
					for (SvdInterrupt interrupt : peripheral.getInterrupts()) {
						if (interrupt.matchesBitPosition(bit)) {
							affectedInterrupts.add(interrupt.getFormattedInfo());
							break;
						}
					}
				}
			}
			
			if (affectedInterrupts.isEmpty()) {
				return null;
			}
			
			// Format the interrupt context
			StringBuilder context = new StringBuilder();
			if (regName.contains("INTENSET") || regName.contains("ENABLE")) {
				context.append("Enabling IRQ: ");
			} else if (regName.contains("INTENCLR") || regName.contains("DISABLE")) {
				context.append("Disabling IRQ: ");
			} else {
				context.append("IRQ: ");
			}
			
			// Add interrupt names
			for (int i = 0; i < affectedInterrupts.size(); i++) {
				if (i > 0) context.append(", ");
				context.append(affectedInterrupts.get(i));
				if (i >= 2) { // Limit to first 3 interrupts
					context.append("...");
					break;
				}
			}
			
			return context.toString();
			
		} catch (Exception e) {
			return null;
		}
	}
	
	/**
	 * Determine the active cluster mode for a peripheral based on the MODE field value
	 * in the control register (CTRL/CTRLA). This implements the generic pattern where
	 * peripherals with clusters have a control register with a MODE field that determines
	 * which cluster mode is active.
	 * 
	 * @param peripheral The peripheral to analyze
	 * @param usedPeripherals Set of all used peripherals (for cross-referencing)
	 * @return The active mode name from enumerated values, or null if cannot determine
	 */
	private String determineActiveClusterMode(SvdPeripheral peripheral, Set<SvdPeripheral> usedPeripherals) {
		try {
			// Look for control registers (CTRL, CTRLA, CTRLB) in this peripheral
			SvdRegister controlRegister = findControlRegister(peripheral);
			if (controlRegister == null) {
				return null;
			}
			
			// Find the MODE field in the control register
			var modeField = findModeField(controlRegister);
			if (modeField == null || !modeField.hasEnumeratedValues()) {
				return null;
			}
			
			// Read the current value of the control register to determine active mode
			long controlRegisterAddress = peripheral.getBaseAddr() + controlRegister.getOffset();
			Long currentValue = readCurrentRegisterValue(controlRegisterAddress);
			if (currentValue == null) {
				return null;
			}
			
			// Extract the MODE field value from the register
			long modeFieldValue = modeField.extractValue(currentValue);
			
			// Find the enumerated value that matches this mode
			var activeEnumValue = modeField.findEnumeratedValue(modeFieldValue);
			if (activeEnumValue != null) {
				return activeEnumValue.getName();
			}
			
			return null;
		} catch (Exception e) {
			// If anything fails, fall back to default cluster name
			return null;
		}
	}
	
	/**
	 * Find a control register (CTRL, CTRLA, CTRLB) in the given peripheral
	 */
	private SvdRegister findControlRegister(SvdPeripheral peripheral) {
		for (SvdRegister reg : peripheral.getRegisters()) {
			String regName = reg.getName().toUpperCase();
			if (regName.equals("CTRL") || regName.equals("CTRLA") || regName.equals("CTRLB") ||
				regName.endsWith("_CTRL") || regName.endsWith("_CTRLA") || regName.endsWith("_CTRLB")) {
				return reg;
			}
		}
		return null;
	}
	
	/**
	 * Find the MODE field in the given register
	 */
	private io.svdparser.SvdField findModeField(SvdRegister register) {
		for (var field : register.getFields()) {
			if (field.getName().toUpperCase().equals("MODE")) {
				return field;
			}
		}
		return null;
	}
	
	/**
	 * Inner class to hold mode information including name and description
	 */
	private static class ModeInfo {
		public final String name;
		public final String description;
		
		public ModeInfo(String name, String description) {
			this.name = name;
			this.description = description;
		}
	}
	
	/**
	 * Determine the cluster mode being set based on an immediate value being written
	 * to a control register. This is used when we're analyzing a write operation to
	 * a control register and want to determine what mode is being activated.
	 * 
	 * @param peripheral The peripheral being written to
	 * @param register The register being written to
	 * @param immediateValue The value being written
	 * @return The mode name from enumerated values, or null if cannot determine
	 */
	private String determineClusterModeFromImmediateValue(SvdPeripheral peripheral, SvdRegister register, long immediateValue) {
		var modeInfo = determineClusterModeInfoFromImmediateValue(peripheral, register, immediateValue);
		return (modeInfo != null) ? modeInfo.name : null;
	}
	
	/**
	 * Determine the cluster mode information (name and description) being set based on 
	 * an immediate value being written to a control register.
	 * 
	 * @param peripheral The peripheral being written to
	 * @param register The register being written to
	 * @param immediateValue The value being written
	 * @return ModeInfo with name and description, or null if cannot determine
	 */
	private ModeInfo determineClusterModeInfoFromImmediateValue(SvdPeripheral peripheral, SvdRegister register, long immediateValue) {
		try {
			// Check if this is a control register
			String regName = register.getName().toUpperCase();
			boolean isControlRegister = regName.equals("CTRL") || regName.equals("CTRLA") || regName.equals("CTRLB") ||
									   regName.endsWith("_CTRL") || regName.endsWith("_CTRLA") || regName.endsWith("_CTRLB");
			
			if (!isControlRegister) {
				return null;
			}
			
			// Find the MODE field in this register
			var modeField = findModeField(register);
			if (modeField == null || !modeField.hasEnumeratedValues()) {
				return null;
			}
			
			// Extract the MODE field value from the immediate value being written
			long modeFieldValue = modeField.extractValue(immediateValue);
			
			// Find the enumerated value that matches this mode
			var activeEnumValue = modeField.findEnumeratedValue(modeFieldValue);
			if (activeEnumValue != null) {
				return new ModeInfo(activeEnumValue.getName(), activeEnumValue.getDescription());
			}
			
			return null;
		} catch (Exception e) {
			return null;
		}
	}
	
	/**
	 * Read the current value of a register from memory
	 */
	private Long readCurrentRegisterValue(long registerAddress) {
		try {
			AddressSpace addrSpace = mProgram.getAddressFactory().getDefaultAddressSpace();
			Address addr = addrSpace.getAddress(registerAddress);
			
			// Check if memory exists at this address
			MemoryBlock memBlock = mMemory.getBlock(addr);
			if (memBlock == null) {
				return null;
			}
			
			// Try to read as 32-bit value (most common for control registers)
			try {
				int value32 = mMemory.getInt(addr);
				return (long) value32 & 0xFFFFFFFFL;
			} catch (Exception e) {
				// Try 16-bit if 32-bit fails
				try {
					short value16 = mMemory.getShort(addr);
					return (long) value16 & 0xFFFFL;
				} catch (Exception e2) {
					// Try 8-bit if 16-bit fails
					try {
						byte value8 = mMemory.getByte(addr);
						return (long) value8 & 0xFFL;
					} catch (Exception e3) {
						return null;
					}
				}
			}
		} catch (Exception e) {
			return null;
		}
	}
	
}
