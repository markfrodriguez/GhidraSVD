# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

GhidraSVD is a Ghidra extension that imports CMSIS SVD (System View Description) files to populate memory maps for firmware reverse engineering. It parses SVD files containing peripheral register definitions and creates memory blocks, symbols, data types, and comments in Ghidra projects.

## Build Commands

**Environment Setup:**
- Set `GHIDRA_INSTALL_DIR` environment variable to your Ghidra installation directory
- Requires Java 17 or later

**Essential Commands:**
```bash
# Build the extension
./gradlew build

# Create extension ZIP package for distribution
./gradlew buildExtension

# Install extension directly to Ghidra
./gradlew installExtension

# Setup debugging (recommended method)
./gradlew debugExtension

# Clean build artifacts
./gradlew clean
```

**Debugging Workflow:**
1. Run `./gradlew debugExtension` to prepare extension and get instructions
2. Launch Ghidra with debug agent: `cd $GHIDRA_INSTALL_DIR && ./support/launch.sh debug jdk Ghidra 4G '' ghidra.GhidraRun`
3. In IntelliJ: Create "Remote JVM Debug" configuration with localhost:18001
4. Set breakpoints and trigger extension functionality in Ghidra

## Architecture

**Core Components:**
- `SVDPlugin.java`: Main plugin class that integrates with Ghidra, provides "Load SVD File..." menu action
- `SvdLoadTask.java`: Background task that parses SVD files and applies them to Ghidra programs
- `SvdFileDialog.java`: File selection dialog for choosing SVD files
- `MemoryUtils.java`: Utilities for memory block collision detection and analysis
- `Block.java`/`BlockInfo.java`: Data structures representing memory regions and their properties

**Enhanced SVD Parser Components:**
- `SvdInterrupt.java`: Enhanced interrupt handling with improved bit-to-interrupt matching
- `SvdField.java`: Enhanced field analysis with enumerated value support
- `SvdEnumeratedValue.java`: Support for enumerated field values with name/description/value
- `SvdRegister.java`: Enhanced register handling with cluster support
- `SvdPeripheral.java`: Enhanced peripheral parsing with interrupt and cluster support

**Key Dependencies:**
- `svd-parser-v0.0.8.jar`: External library for parsing CMSIS SVD XML files (enhanced with cluster support)
- Ghidra Framework and Features JARs (compile-time only)

**Enhanced Processing Flow:**
1. User selects "File > Load SVD File..." in Ghidra CodeBrowser
2. `SVDPlugin` launches `SvdLoadTask` with selected SVD file
3. `SvdLoadTask` parses SVD using enhanced `io.svdparser.SvdDevice`
4. Creates memory blocks from peripheral address blocks
5. Generates symbols in "Peripherals" namespace
6. Creates structured data types for register layouts
7. **Enhanced**: Adds comprehensive SVD-based comments with:
   - Dynamic cluster mode detection (e.g., `RTC[CLOCK]` instead of `RTC[MODE0]`)
   - Interrupt context analysis (`[Enabling IRQ: EIC_INTREQ_15 (IRQ 27)]`)
   - Read/write operation detection (`<==` for writes, `==>` for reads)
   - Immediate value analysis with hex formatting
   - Rich mode context (`[Mode: Mode 2: Clock/Calendar]`)
8. **Main Function Detection**: Automatically identifies the application main entry point using ARM Cortex-M reset vector analysis and startup code flow tracing

**Extension Structure:**
The built extension contains compiled classes in `lib/GhidraSVD.jar`, the SVD parser dependency, source archive, and metadata files following Ghidra extension format.

## SVD Comment Format

The extension generates structured comments following patterns documented in `SVD_COMMENT_FORMAT.md`. Current format provides comprehensive information but is planned for standardization to improve machine parseability while maintaining human readability.

**Current Format Example:**
```
SVD: RTC[CLOCK].CTRLA - Real-Time Counter; MODE0 Control A [16-bit] {MODE:Mode 2: Clock/Calendar (0x2)} <== 0x8182 [Mode: Mode 2: Clock/Calendar]
```

**Key Features:**
- Dynamic cluster mode resolution based on MODE field values
- Comprehensive interrupt context for interrupt-related registers
- Field analysis with enumerated value descriptions
- Directional indicators for read/write operations

## Main Function Detection

The extension automatically identifies the application main entry point during SVD loading using sophisticated ARM Cortex-M analysis.

**Detection Algorithm:**
1. **Reset Vector Analysis**: Reads the reset handler address from the ARM Cortex-M vector table at memory offset 0x4
2. **Startup Flow Tracing**: Follows function calls from the reset handler through initialization code
3. **Heuristic Analysis**: Identifies main using multiple criteria:
   - Function size (typically >20 instructions for embedded applications)
   - Call depth from reset handler (handles direct calls and nested startup sequences)
   - Application-level function calls (bl/blx instructions to non-startup code)
   - Main-like structure (loops, conditional branches indicating application logic)

**Main Identification Comment:**
When detected, adds an end-of-line comment:
```
SVD: Main entry point - Application start (auto-identified from reset vector analysis)
```

**Key Methods:**
- `identifyMainEntryPoint()`: Main detection orchestrator
- `findResetHandlerFromVectorTable()`: ARM vector table parsing
- `analyzeStartupFunction()`: Recursive startup code analysis
- `isLikelyMainFunction()`: Heuristic-based main identification