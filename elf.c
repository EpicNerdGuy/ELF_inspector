#include "elf_parser.h"
#include <sys/types.h>
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>


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

    switch(e_ident[EI_DATA]){
    	case ELFDATA2LSB:
    		printf("ELF is little endian\n");
    		break;
    	case ELFDATA2MSB:
    		printf("ELF is big endian\n");
    		break;
    	default:
    		printf("Invalid format: not ELF\n");
    		break; 
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


}


