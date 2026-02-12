#include "elf_parser.h"
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>


const char* get_machine_name(uint16_t e_machine){

	switch(e_machine){
		case EM_NONE:    return "None (unknown)";
        case EM_M32:     return "WE32100";
        case EM_SPARC:   return "Sparc";
        case EM_386:     return "Intel 80386";
        case EM_68K:     return "MC68000";
        case EM_88K:     return "MC88000";
        case EM_860:     return "Intel 80860";
        case EM_MIPS:    return "MIPS R3000";
        case EM_S370:    return "IBM System/370";
        case EM_ARM:     return "ARM";
        case EM_X86_64:  return "Advanced Micro Devices X86-64";
        case EM_AARCH64: return "ARM AArch64";
        default:         return "Unknown Machine";
	}
}

void display_elf_header(FILE* fp,Elf64_Ehdr header){
	if(header.e_ident[EI_DATA] == ELFDATA2LSB){
		printf("Data: little endian\n");
	}
	else if(header.e_ident[EI_DATA] == ELFDATA2MSB){
		printf("Data: big endian\n");
	}
	else{
		printf("class: invalid class (0x%x)\n",header.e_ident[EI_CLASS]);
	}

	switch(header.e_ident[EI_CLASS]){
		case ELFCLASS64:
			printf("class: 64-bit objects\n");
			break;
		case ELFCLASSNONE:
		default:
			printf("class: invalid class (0x%x)\n",header.e_ident[EI_CLASS]);
			break;
		
	}

	printf("OS/ABI: ");
	switch(header.e_ident[EI_OSABI]){
	case ELFOSABI_NONE:
		printf("UNIX -> System V\n"); break;
	case ELFOSABI_LINUX:
		printf("UNIX -> Linux\n"); break;
	case ELFOSABI_FREEBSD:
		printf("UNIX -> FreeBSD\n"); break;
	case ELFOSABI_ARM:
		printf("UNIX -> ARM Architecture\n"); break;
	default:
		printf("UNKNOWN UNIX\n"); break;
	}

	printf("Machine: %s\n", get_machine_name(header.e_machine));
	printf("Entry point address: 0x%lx\n", header.e_entry);
	printf("Start of program headers: %lu\n",header.e_phoff);
	printf("Start of section headers: %lu\n",header.e_shoff);
}


Elf64_Ehdr elf_header_parser(FILE* fp) {
    Elf64_Ehdr header;
    rewind(fp);

    if (fread(&header, 1, sizeof(header), fp) < sizeof(header)) {
        fprintf(stderr, "ERROR: Could not read full ELF header\n");
        exit(EXIT_FAILURE);
    }

    if (header.e_ident[EI_MAG0] != ELFMAG0 || header.e_ident[EI_MAG1] != 'E') {
        fprintf(stderr, "Error: Not a valid ELF file.\n");
        exit(EXIT_FAILURE);
    }
    return header; 
}

const char* check_pie(Elf64_Ehdr *header){
	return (header -> e_type == ET_DYN) ? "ENABLED" : "DISABLED";
}

void display_security_overview(FILE* fp,Elf64_Ehdr header){
	printf("\x1b[1;32m");
	printf("\n[+] Security Overview:\n");
	printf("----------------\n");
	printf("\x1b[0m\n");
	printf("\x1b[1;32m");
	printf("\x1b[0m");
	const char* PIE;
	PIE = check_pie(&header);
	printf("PIE:	%s\n",PIE);
}

void program_header(FILE* fp,Elf64_Ehdr header){
	Elf64_Phdr phdr;
	if(header.e_phnum == 0){
		printf("No program headers found\n");
		return;
	}
	printf("\x1b[1;32m");
	printf("\n[+] Program Header:\n");
	printf("----------------\n");
	printf("\x1b[0m\n");
	printf("\x1b[1;32m");
	printf("%-15s %-18s %-18s %-10s %-5s\n", "Type", "Offset", "VirtAddr", "FileSize", "Flags");
	printf("\x1b[0m");

	fseek(fp,header.e_phoff,SEEK_SET);

	for(int i = 0; i < header.e_phnum; i++){
		if (fread(&phdr, sizeof(Elf64_Phdr), 1, fp) != 1) break;

		const char* type_str;
        switch (phdr.p_type) {
            case PT_NULL:    	type_str = "NULL";    break;
            case PT_LOAD:    	type_str = "LOAD";    break;
            case PT_DYNAMIC: 	type_str = "DYNAMIC"; break;
            case PT_INTERP:  	type_str = "INTERP";  break;
            case PT_NOTE:    	type_str = "NOTE";    break;
            case PT_PHDR:    	type_str = "PHDR";    break;
            case PT_GNU_STACK:  type_str = "GNU_STACK"; break;
            case PT_SHLIB:		type_str = "SHLIB"; break;
            case PT_TLS:		type_str = "TLS"; break;
            case PT_GNU_RELRO:	type_str = "GNU_RELRO"; break;
            case PT_GNU_EH_FRAME: type_str = "GNU_EH_FRAME"; break;
            case PT_GNU_PROPERTY: type_str = "GNU_PROPERTY"; break;
            default:         type_str = "OTHER";   break;
        }

        char flags[4] = "---";
        if (phdr.p_flags & PF_R) flags[0] = 'R';
        if (phdr.p_flags & PF_W) flags[1] = 'W';
        if (phdr.p_flags & PF_X) flags[2] = 'X';

        printf("%-15s 0x%016lx 0x%016lx 0x%08lx %-5s\n",type_str, phdr.p_offset, phdr.p_vaddr, phdr.p_filesz, flags);
	}


}


 


