# ELF Inspector

### Overview

ELF Inspector is a low-level binary analysis tool designed to parse and display the internal structure of Executable and Linkable Format (ELF) files. It provides detailed insights into file headers, machine architecture, and entry point addresses and program headers, serving as a utility for reverse engineering and software security auditing.

---

### Features

* **Header Parsing**: Extracts core metadata from the ELF header, including class (32-bit vs 64-bit), data encoding (endianness), OS/ABI information, and program headers.
* **Architecture Identification**: Detects the target instruction set architecture, such as x86-64.
* **Address Analysis**: Locates and displays the virtual address of the program entry point.
* **Safety Checks**: Includes validation logic to ensure the target file contains the standard ELF magic bytes before attempting to parse.
* **Modular Inspection**: Use command-line flags to isolate and view only the specific headers you care about.

---

### Technical Details

The tool is written in C and interacts directly with the ELF file structure. It currently supports:

* ELF64 header structures.
* Little-endian and Big-endian data formats.
* Detection of Executable, Shared Object, and Relocatable file types.
* Program header table parsing (Offsets, Virtual Addresses, File Sizes, and Flags).

---

### Installation

To compile the inspector, use a standard C compiler:

```bash
gcc cli.c -o elf_inspector

```

---

### Usage

Run the binary by providing the path to an ELF file using the `-f` flag, followed by the specific headers you want to inspect.

```bash
./elf_inspector [OPTIONS] -f <file>

```

#### Options:

| Short Flag | Long Flag | Description |
| --- | --- | --- |
| `-f` | `--file <file>` | Path to the ELF binary to inspect **(Required)** |
| `-a` | `--all` | Display **ALL** headers (ELF + Program) |
| `-e` | `--eh` | Parse and display only the **ELF Header** |
| `-p` | `--ph` | Parse and display only the **Program Header Table** |
| `-h` | `--help` | Display the help menu |

#### Examples:

**View only the ELF Header:**

```bash
./elf_inspector -f /bin/ls -e

```

**View only the Program Headers:**

```bash
./elf_inspector -f /bin/ls -p

```

**View everything (ELF + Program headers):**

```bash
./elf_inspector -f /bin/ls --all

```

---

### Example Output

```text
  ______ _      ______   _____ _   _  _____ _____  ______ _____ _______ ____  _____  
 |  ____| |    |  ____| |_   _| \ | |/ ____|  __ \|  ____/ ____|__   __/ __ \|  __ \ 
 | |__  | |    | |__      | | |  \| | (___ | |__) | |__ | |       | | | |  | | |__) |
 |  __| | |    |  __|     | | | . ` |\___ \|  ___/|  __|| |       | | | |  | |  _  / 
 | |____| |____| |       _| |_| |\  |____) | |    | |___| |____   | | | |__| | | \ \ 
 |______|______|_|      |_____|_| \_|_____/|_|    |______\_____|  |_|  \____/|_|  \_\

          >> Advanced Binary Analysis & ELF Structure Inspector <<
                      v1.0 | Reverse Engineering Tool
=====================================================================================

[+] ELF Header:
----------------

Data: little endian
class: 64-bit objects
OS/ABI: UNIX -> System V
Machine: Advanced Micro Devices X86-64
Entry point address: 0x6760
Start of program headers: 64
Start of section headers: 156712

[+] Program Header:
----------------

Type            Offset             VirtAddr           FileSize   Flags
PHDR            0x0000000000000040 0x0000000000000040 0x00000310 R--  
INTERP          0x0000000000000394 0x0000000000000394 0x0000001c R--  
LOAD            0x0000000000000000 0x0000000000000000 0x00003810 R--  
LOAD            0x0000000000004000 0x0000000000004000 0x00016cf9 R-X  
LOAD            0x000000000001b000 0x000000000001b000 0x00009538 R--  
LOAD            0x0000000000024fb0 0x0000000000025fb0 0x000012d0 RW-  
DYNAMIC         0x00000000000259f8 0x00000000000269f8 0x00000210 RW-  
NOTE            0x0000000000000350 0x0000000000000350 0x00000020 R--  
NOTE            0x0000000000000370 0x0000000000000370 0x00000024 R--  
NOTE            0x0000000000024518 0x0000000000024518 0x00000020 R--  
GNU_PROPERTY    0x0000000000000350 0x0000000000000350 0x00000020 R--  
GNU_EH_FRAME    0x0000000000020388 0x0000000000020388 0x00000a74 R--  
GNU_STACK       0x0000000000000000 0x0000000000000000 0x00000000 RW-  
GNU_RELRO       0x0000000000024fb0 0x0000000000025fb0 0x00001050 R--  

[+] Security Overview:
----------------

PIE:	ENABLED


```
