# SVD Comment Format Documentation

## Overview

The GhidraSVD extension generates structured comments for peripheral register access instructions. These comments are designed to be both human-readable and machine-parseable for automated analysis tools.

## Current SVD Format Specification

### Format Structure
```
SVD: <PERIPHERAL>[<CLUSTER>].<REGISTER>|<PERIPHERAL_DESC>|<CLUSTER_DESC>|<REGISTER_DESC>|<SIZE>|<OPERATION>|<FIELDS>|<INTERRUPTS>|<MODE_CONTEXT>
```

### Components

#### 1. Header and Register Identification
- **SVD:** - Format identifier
- **PERIPHERAL** - Peripheral name (e.g., `EIC`, `RTC`, `SERCOM5`)  
- **CLUSTER** - Cluster/mode name (e.g., `MODE2`, `I2CM`, `CLOCK`) or `N/A`
- **REGISTER** - Register name (e.g., `CTRLA`, `INTENSET`, `SYNCBUSY`)

#### 2. Descriptions (Pipe-Delimited)
- **PERIPHERAL_DESC** - Peripheral description from SVD (e.g., `Real-Time Counter`)
- **CLUSTER_DESC** - Cluster/mode description from SVD (e.g., `Clock/Calendar MODE2`) or `N/A`
- **REGISTER_DESC** - Register description from SVD (e.g., `Synchronization Busy Status`)

#### 3. Register Properties
- **SIZE** - Register width in bits (e.g., `16`, `32`)
- **OPERATION** - Operation type:
  - `READ` - Read operation
  - `WRITE:0xVALUE` - Write operation with hex value
  - `WRITE:UNKNOWN` - Write operation with undetermined value

#### 4. Field Analysis
**Format:** `FIELD_NAME:OFFSET:WIDTH(VALUE):FIELD_DESCRIPTION:ENUMERATED_VALUE_DESCRIPTION`

**Components:**
- **FIELD_NAME** - Field name from SVD (e.g., `MODE`, `ENABLE`, `SWRST`)
- **OFFSET** - Bit offset within register (e.g., `0`, `15`)
- **WIDTH** - Field width in bits (e.g., `1`, `2`)
- **VALUE** - Current field value in hex (e.g., `0x0`, `0x2`)
- **FIELD_DESCRIPTION** - Field description from SVD
- **ENUMERATED_VALUE_DESCRIPTION** - Description of current enumerated value (optional)

**Multiple fields separated by commas**

#### 5. Interrupt Context
**Format:** `ACTION:INTERRUPT_NAME:VECTOR_NUMBER`

**Components:**
- **ACTION** - Interrupt action (`ENABLE`, `DISABLE`, `STATUS`)
- **INTERRUPT_NAME** - Interrupt name from SVD (e.g., `EIC_INTREQ_15`)
- **VECTOR_NUMBER** - Interrupt vector number (e.g., `27`)

**Multiple interrupts separated by commas, or `N/A` if none**

#### 6. Mode Context
Additional mode information for cluster registers (e.g., `Mode 2: Clock/Calendar`) or `N/A`

## Complete Examples

### Read Operation with Multiple Fields
```
SVD: RTC[MODE2].SYNCBUSY|Real-Time Counter|Clock/Calendar MODE2|Synchronization Busy Status|32|READ|SWRST:0:1(0x0):Software Reset Bit Busy:Reset operation not busy,ENABLE:1:1(0x0):Enable Bit Busy:Enable operation not busy,FREQCORR:2:1(0x0):FREQCORR Register Busy:Frequency correction not busy,CLOCK:3:1(0x0):CLOCK Register Busy:Clock register not busy|N/A|N/A
```

### Write Operation with Interrupt Context
```
SVD: EIC.INTENSET|External Interrupt Controller|N/A|Interrupt Enable Set|16|WRITE:0x8000|EXTINT:15:1(0x1):External Interrupt 15 Enable:Enable interrupt 15|ENABLE:EIC_INTREQ_15:27|N/A
```

### Write Operation with Mode Context
```
SVD: RTC[CLOCK].CTRLA|Real-Time Counter|Clock/Calendar Mode|Control A|16|WRITE:0x8182|MODE:0:2(0x2):Operating Mode:Mode 2 Clock/Calendar,ENABLE:1:1(0x1):Enable:Enable the peripheral|N/A|Mode 2: Clock/Calendar
```

### Standard Register without Cluster
```
SVD: PORT.OUT2|Input/Output Port|N/A|Data Output Value|32|READ|OUT0:0:1(0x0):Output Data Bit 0:Pin output low,OUT1:1:1(0x1):Output Data Bit 1:Pin output high|N/A|N/A
```

## Legacy Format (Previous Implementation)

The previous format used inconsistent delimiters and nested structures:

```
SVD: EIC.INTENSET - External Interrupt Controller; Interrupt Enable Set [16-bit] {EXTINT:External Interrupt 15 Enable (0x1)} <== 0x8000 [Enabling IRQ: EIC_INTREQ_15 (IRQ 27)]
```

**Parsing Limitations:**
1. Inconsistent delimiters (`;`, `-`, `[`, `{`, etc.)
2. Nested structures difficult to parse
3. Mixed data types and variable ordering
4. No clear field structure

## Parsing the Current Format

### Regular Expression Pattern
```regex
^SVD: ([^|]+)\|([^|]+)\|([^|]+)\|([^|]+)\|(\d+)\|([^|]+)\|([^|]*)\|([^|]*)\|([^|]*)$
```

### Field Parsing
```regex
([^:]+):(\d+):(\d+)\(0x([A-Fa-f0-9]+)\):([^:]*):?(.*)
```

### Interrupt Parsing
```regex
([^:]+):([^:]+):(\d+)
```

## Benefits of Current Format

1. **Consistent Structure** - Fixed pipe delimiters and field ordering
2. **Machine Parseable** - Single regex pattern captures all components
3. **Human Readable** - Clear hierarchical information
4. **Complete Information** - Captures all SVD hierarchical details
5. **Escape Safe** - Pipe delimiters avoid conflicts with descriptions

## Regex Patterns for Current Format

For tools that need to parse the current format:

```regex
# Basic SVD comment
^SVD: (.+)$

# Peripheral.Register extraction
^SVD: ([A-Z0-9_]+)(?:\[([A-Z0-9_]+)\])?\.([A-Z0-9_]+)

# Operation extraction  
(<==|==>|\@) (?:0x([A-Fa-f0-9]+)|\?|0x([A-Fa-f0-9]+))

# Field analysis extraction
\{([^}]+)\}

# Interrupt context extraction
\[([^\]]+)\]

# Individual field parsing
([A-Z0-9_]+):([^(]+)\(0x([A-Fa-f0-9]+)\)

# Interrupt parsing
(Enabling|Disabling|)\s*IRQ:\s*([A-Z0-9_]+)\s*\(IRQ\s*(\d+)\)
```

## Use Cases for Automated Analysis

1. **Firmware flow analysis** - Track peripheral initialization sequences
2. **Interrupt dependency mapping** - Identify interrupt enable/disable patterns
3. **Power management analysis** - Monitor peripheral enable/disable operations
4. **Security analysis** - Detect privileged peripheral access patterns
5. **Performance optimization** - Identify register access hotspots
6. **Hardware abstraction** - Generate higher-level API documentation
7. **Test coverage** - Verify all peripheral registers are accessed during testing