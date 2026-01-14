#include "elf.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>


void elf_header_parser(FILE* fp){
	switch(e_dent[EI_CLASS]){
		case ELFCLASS32:
			printf("ELF class: 32-bit objects\n");
			break;
		case ELFCLASS64:
			printf("ELF class: 64-bit objects\n");
			break;
		case ELFCLASSNONE:
		default:
			printf("ELF class: invalid class (0x%x)\n",e_dent(EI_CLASS));
			break;
		
	}	
}


