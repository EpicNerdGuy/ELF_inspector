### Overview

ELF Inspector is a low-level binary analysis tool designed to parse and display the internal structure of Executable and Linkable Format (ELF) files. It provides detailed insights into file headers, machine architecture, and entry point addresses and program headers serving as a utility for reverse engineering and software security auditing.

---

### Features

* **Header Parsing**: Extracts core metadata from the ELF header, including class (32-bit vs 64-bit), data encoding (endianness), and OS/ABI information and program headers.
* **Architecture Identification**: Detects the target instruction set architecture, such as x86-64.
* **Address Analysis**: Locates and displays the virtual address of the program entry point.
* **Safety Checks**: Includes validation logic to ensure the target file contains the standard ELF magic bytes before attempting to parse.

---

### Technical Details

The tool is written in C and interacts directly with the ELF file structure. It currently supports:

* ELF64 header structures.
* Little-endian and Big-endian data formats.
* Detection of Executable, Shared Object, and Relocatable file types.
* Program headers

---

### Installation

To compile the inspector, use a standard C compiler:

```bash
gcc cli.c -o elf_inspector

```

---

### Usage

Run the binary by providing the path to an ELF file as a command line argument:

```bash
./elf_inspector <path_to_binary>

```

**Example output:**

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

ELF Header info:
----------------
Data: little endian
class: 64-bit objects
OS/ABI: UNIX -> System V
Machine: Advanced Micro Devices X86-64
Entry point address: 0x10f0
Start of program headers: 64
Start of section headers: 14696

Program Header info:
----------------
Type            Offset             VirtAddr           FileSize   Flags
PHDR            0x0000000000000040 0x0000000000000040 0x00000348 R--  
INTERP          0x00000000000003cc 0x00000000000003cc 0x0000001c R--  
LOAD            0x0000000000000000 0x0000000000000000 0x000008c8 R--  
LOAD            0x0000000000001000 0x0000000000001000 0x000009b9 R-X  
LOAD            0x0000000000002000 0x0000000000002000 0x000009d0 R--  
LOAD            0x0000000000002dd0 0x0000000000003dd0 0x00000298 RW-  
DYNAMIC         0x0000000000002de0 0x0000000000003de0 0x000001e0 RW-  
NOTE            0x0000000000000388 0x0000000000000388 0x00000020 R--  
NOTE            0x00000000000003a8 0x00000000000003a8 0x00000024 R--  
NOTE            0x00000000000029b0 0x00000000000029b0 0x00000020 R--  
OTHER           0x0000000000000388 0x0000000000000388 0x00000020 R--  
OTHER           0x0000000000002774 0x0000000000002774 0x0000004c R--  
OTHER           0x00000000000028f8 0x00000000000028f8 0x000000b5 R--  
GNU_STACK       0x0000000000000000 0x0000000000000000 0x00000000 RW-  
OTHER           0x0000000000002dd0 0x0000000000003dd0 0x00000230 R--  
