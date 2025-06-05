# GhidraSVD Enhanced Plugin - SVD Comments Feature

## Overview

The enhanced GhidraSVD plugin now automatically adds **persistent comments** to disassembly instructions that reference SVD-defined registers. These comments are stored in Ghidra's database and will be visible in all views including the disassembly listing returned by `getListing()` method calls.

## What Changed

### Before (Original Plugin)
- SVD information was only displayed in the CodeBrowser view
- Information was not stored in Ghidra's database
- `getListing()` method calls would not include SVD information
- Information would disappear when switching views or tools

### After (Enhanced Plugin)
- SVD information is stored as **end-of-line (EOL) comments** in the database
- Comments are persistent and visible in all Ghidra views
- `getListing()` method calls include SVD comments
- Information remains available across sessions and tools

## How It Works

### 1. SVD File Processing
When you load an SVD file using **File → Load SVD File...**:

1. **Memory blocks** are created for peripherals
2. **Symbols** are created for peripheral base addresses
3. **Data types** are created for register structures
4. **NEW: Comments are added** to instructions that reference SVD registers

### 2. Comment Generation
The plugin scans all instructions in the program and:

- Identifies memory references in instruction operands
- Matches memory addresses against SVD register definitions
- Adds comments with register information

### 3. Enhanced Comment Format
Comments are now added with comprehensive information in the format:
```
SVD: <Peripheral>.<Register> - <PeripheralDesc> - <RegisterDesc> [<Size>-bit] @0x<Offset>
```

For example:
```
str r0,[r3,#0x4]     ; SVD: GCLK.SYNCBUSY - Generic Clock Generator - Synchronization Busy [32-bit] @0x4
```

**What each part means:**
- **GCLK** - Peripheral name 
- **SYNCBUSY** - Register name  
- **Generic Clock Generator** - Peripheral description from SVD
- **Synchronization Busy** - Register description from SVD
- **[32-bit]** - Register size in bits
- **@0x4** - Register offset within peripheral

**Fallback formats when descriptions aren't available:**
- If only register description: `SVD: GCLK.SYNCBUSY - Synchronization Busy [32-bit] @0x4`
- If only peripheral description: `SVD: GCLK.SYNCBUSY - Generic Clock Generator [32-bit] @0x4`
- If no descriptions: `SVD: GCLK.SYNCBUSY [32-bit] @0x4`

### 4. Partial Register Access
The plugin handles partial register accesses (byte/halfword accesses to 32-bit registers):
```
ldrb r0,[r3,#0x21]    ; SVD: GCLK.SYNCBUSY - Synchronization Busy [32-bit] @0x20 (+0x1)
```
The `(+0x1)` indicates a byte access 1 byte into the 32-bit register.

## Key Features

### ✅ **Persistent Storage**
- Comments are stored in Ghidra's database
- Survive program saves/loads
- Visible in all analysis tools

### ✅ **Intelligent Merging**
- Preserves existing comments
- Prevents duplicate SVD comments
- Appends to existing comments with "; " separator

### ✅ **Comprehensive Scanning**
- Scans all instructions in the program
- Handles multiple operands per instruction
- Supports all memory reference types

### ✅ **Flexible Address Matching**
- Exact address matches
- Partial register access detection
- Handles byte/halfword accesses to word registers

## API Usage

With the enhanced plugin, you can now access SVD information through standard Ghidra APIs:

```java
// Get the listing
Listing listing = program.getListing();

// Get instruction at specific address
Instruction instruction = listing.getInstructionAt(address);

// Get SVD comment (now includes SVD information!)
String comment = listing.getComment(CodeUnit.EOL_COMMENT, instruction.getAddress());

// The comment will include SVD information like:
// "SVD: RTC.CTRL - Real-time Clock Control Register"
```

## Implementation Details

### New Methods Added

1. **`addSvdCommentsToInstructions(BlockInfo blockInfo)`**
   - Main entry point for adding SVD comments
   - Called automatically after processing each peripheral block

2. **`addSvdCommentsToInstructions(BlockInfo blockInfo, boolean preserveExistingComments, boolean onlyCurrentBlock)`**
   - Enhanced version with options:
     - `preserveExistingComments`: Append to existing comments vs. replace them
     - `onlyCurrentBlock`: Process only current peripheral block vs. entire program

3. **`findMatchingRegister(long targetAddr, Map<Long, String> registerMap)`**
   - Matches target addresses to SVD registers
   - Handles exact matches and partial register accesses
   - Returns formatted register information

### Processing Flow

```
1. Load SVD File
   ↓
2. Create Memory Blocks
   ↓
3. Create Symbols
   ↓
4. Create Data Types
   ↓
5. *** NEW *** Add SVD Comments to Instructions
   ↓
6. Complete
```

## Benefits

### For Users
- **Persistent documentation**: SVD information is always available
- **Better analysis**: Comments help understand code behavior
- **Export compatibility**: Comments included in disassembly exports

### For Developers
- **API access**: SVD information available through standard Ghidra APIs
- **Tool integration**: Works with all Ghidra analysis tools
- **Scriptable**: Comments can be accessed and processed by scripts

## Usage Instructions

1. **Install the enhanced plugin** (already done with `./gradlew installExtension`)
2. **Restart Ghidra** to load the new plugin version
3. **Open your program** in Ghidra
4. **Load SVD file**: File → Load SVD File...
5. **Select your SVD file** and wait for processing
6. **View results**: Check the disassembly for new SVD comments

## Example Output

Before:
```
00001b2a 18 62           str        r0,[r3,#0x20]
```

After:
```
00001b2a 18 62           str        r0,[r3,#0x20]     ; SVD: RTC.CTRL - Real-time Clock Control Register
```

The SVD information is now **permanently stored** in the database and accessible through all Ghidra APIs! 🎉

