#include "elf_parser.h"
#include <sys/types.h>
#include <stdio.h>
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



void elf_header_parser(FILE* fp){

	Elf64_Ehdr header;
	unsigned char e_ident[EI_NIDENT];
	

	if(fread(&header,1,sizeof(header),fp) < sizeof(header)){
		printf("ERROR: Could not read full elf header\n");
		return;
	}

	if (header.e_ident[EI_MAG0] != ELFMAG0 || 
        header.e_ident[EI_MAG1] != 'E'      || 
        header.e_ident[EI_MAG2] != 'L'      || 
        header.e_ident[EI_MAG3] != 'F') {
        printf("Error: This is not a valid ELF file.\n");
        return;
    }

	if(header.e_ident[EI_DATA] == ELFDATA2LSB){
		printf("ELF is little endian\n");
	}
	else if(header.e_ident[EI_DATA] == ELFDATA2MSB){
		printf("ELF is big endian\n");
	}
	else{
		printf("ELF class: invalid class (0x%x)\n",header.e_ident[EI_CLASS]);
	}

	switch(header.e_ident[EI_CLASS]){
		case ELFCLASS32:
			printf("ELF class: 32-bit objects\n");
			break;
		case ELFCLASS64:
			printf("ELF class: 64-bit objects\n");
			break;
		case ELFCLASSNONE:
		default:
			printf("ELF class: invalid class (0x%x)\n",header.e_ident[EI_CLASS]);
			break;
		
	}

	printf("Machine: %s\n", get_machine_name(header.e_machine));

	printf("Entry point address: 0x%lx\n", header.e_entry);


}


 


