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

**Key Dependencies:**
- `svd-parser-v0.0.8.jar`: External library for parsing CMSIS SVD XML files
- Ghidra Framework and Features JARs (compile-time only)

**Processing Flow:**
1. User selects "File > Load SVD File..." in Ghidra CodeBrowser
2. `SVDPlugin` launches `SvdLoadTask` with selected SVD file
3. `SvdLoadTask` parses SVD using `io.svdparser.SvdDevice`
4. Creates memory blocks from peripheral address blocks
5. Generates symbols in "Peripherals" namespace
6. Creates structured data types for register layouts
7. Adds SVD-based comments to existing instructions that reference registers

**Extension Structure:**
The built extension contains compiled classes in `lib/GhidraSVD.jar`, the SVD parser dependency, source archive, and metadata files following Ghidra extension format.