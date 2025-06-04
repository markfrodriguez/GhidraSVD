# Building GhidraSVD Extension

## Prerequisites

1. **Java 17 or later** - Required for compilation
2. **Ghidra** - Set `GHIDRA_INSTALL_DIR` environment variable to your Ghidra installation directory
3. **Gradle** - Included via Gradle Wrapper (gradlew)

## Environment Setup

Make sure your `GHIDRA_INSTALL_DIR` environment variable is set:

```bash
export GHIDRA_INSTALL_DIR=/path/to/your/ghidra/installation
```

Currently set to: `${GHIDRA_INSTALL_DIR:-'not set'}`

## Building the Extension

### Using Gradle Wrapper (Recommended)

```bash
# Build the project
./gradlew build

# Create extension ZIP package
./gradlew buildExtension

# Clean build artifacts
./gradlew clean
```

### IntelliJ IDEA Setup

1. **Generate IntelliJ project files:**
   ```bash
   ./gradlew idea
   ```

2. **Open in IntelliJ:**
   - Open IntelliJ IDEA
   - File → Open → Select the `GhidraSVD.ipr` file
   - Or just open the project directory, IntelliJ will auto-detect the Gradle project

3. **Alternative: Import as Gradle project:**
   - File → New → Project from Existing Sources
   - Select the project directory
   - Choose "Import project from external model" → Gradle
   - Follow the wizard

## Available Gradle Tasks

- `./gradlew build` - Compile and build the project
- `./gradlew buildExtension` - Create extension ZIP in `dist/` directory
- `./gradlew installExtension` - Build and install extension to Ghidra extensions directory
- `./gradlew debugExtension` - **RECOMMENDED** - Setup extension for debugging with instructions
- `./gradlew debugGhidra` - Launch Ghidra with debug agent (may cause UI issues)
- `./gradlew debugGhidraAlt` - Alternative debug method using JavaExec
- `./gradlew idea` - Generate IntelliJ IDEA project files
- `./gradlew clean` - Clean build artifacts

## Debugging (Recommended Method)

### Step 1: Prepare Extension for Debugging
```bash
./gradlew debugExtension
```
This will build and install the extension with debug information and provide detailed instructions.

### Step 2: Launch Ghidra with Debug Agent

**Method 1 (Recommended): Use Ghidra's built-in debug script**
```bash
cd "${GHIDRA_INSTALL_DIR}"
./support/launch.sh debug jdk Ghidra 4G '' ghidra.GhidraRun
```
*This uses port 18001 (Ghidra's default debug port)*

**Method 2: Use custom debug port**
```bash
cd "${GHIDRA_INSTALL_DIR}"
./ghidraRun -Xdebug -Xrunjdwp:transport=dt_socket,server=y,suspend=n,address=5005
```
*This uses port 5005*

### Step 3: Attach IntelliJ Debugger
1. In IntelliJ IDEA: **Run → Edit Configurations**
2. Click **+** and select **Remote JVM Debug**
3. Set **Host**: `localhost`, **Port**: `18001` (for Method 1) or `5005` (for Method 2)
4. Click **Debug** to attach to the running Ghidra process

### Step 4: Debug the Extension
1. Set breakpoints in your extension code
2. In Ghidra, trigger extension functionality (e.g., load an SVD file)
3. IntelliJ will hit breakpoints and allow debugging

**Benefits of this method:**
- ✅ No UI responsiveness issues
- ✅ Better debugging experience
- ✅ Can restart debugging without restarting Ghidra
- ✅ Ghidra runs in its normal environment

## Alternative Debugging Methods

### Legacy Method (may cause UI issues)
```bash
./gradlew debugGhidra
```
This launches Ghidra directly with debug agent but may cause UI responsiveness problems.

## Extension Installation

### Automatic Installation (Recommended)
```bash
# Build and install extension automatically
./gradlew installExtension
```
This will:
- Build the extension with compiled classes
- Extract the extension to Ghidra's Extensions directory
- Clean up any previous installations

### Manual Installation
```bash
# Build extension ZIP package
./gradlew buildExtension
```
Then install in Ghidra:
1. File → Install Extensions
2. Click the "+" button and select `dist/GhidraSVD.zip`
3. Restart Ghidra

**Note:** Both methods create the proper extension structure with compiled classes in the `lib/` directory, which is what Ghidra expects.

## Project Structure

```
├── src/main/java/          # Java source files
├── src/main/resources/     # Resource files  
├── doc/                    # Documentation and images
├── .github/                # GitHub workflows and config
├── extension.properties    # Extension metadata
├── Module.manifest        # Module manifest
├── README.md              # Project documentation
├── build.gradle           # Gradle build script
├── settings.gradle        # Gradle settings
└── dist/                  # Built extension packages
```

## Extension Package Contents

The built extension (`dist/GhidraSVD.zip`) contains:

```
GhidraSVD/
├── extension.properties    # Extension metadata
├── Module.manifest        # Module manifest (empty)
├── README.md              # Project documentation
├── lib/                   # Extension JARs and dependencies
│   ├── GhidraSVD.jar      # Compiled extension classes
│   ├── svd-parser-v0.0.8.jar # SVD parsing dependency
│   └── GhidraSVD-src.zip  # Source code archive
├── doc/                   # Documentation
│   ├── logo.png           # Extension logo
│   └── Develop.md         # Development guide
└── .github/               # GitHub workflows and configuration
    ├── dependabot.yml
    └── workflows/
        ├── codeql.yml
        └── main.yml
```

This structure matches the official GhidraSVD extension format.

