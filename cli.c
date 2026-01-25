#include "elf_parser.h"
#include <stdio.h>
#include <stdlib.h>
#define BUFFER_SIZE 4

int main(int argc,char* argv[]){
	unsigned char e_ident[EI_NIDENT];
	FILE* fp;
	unsigned char buffer[BUFFER_SIZE];
	size_t byteread;
	int count = 0;
	char elf_magic_bytes[4] = {
		0x7F,
		0x45,
		0x4C,
		0x46
	};

	if(argc != 2){
		printf("elf-inspector [BINARY]\n");
		return 1;
	}
        
	fp = fopen(argv[1],"rb");
	if (fp == NULL){
		fprintf(stderr,"Error opening file %s",argv[1]);
		return EXIT_FAILURE;
	}

	byteread = fread(buffer,1,4,fp);
	
	if(byteread < 4){
		printf("ELF file too small\n");
	}

	for(int i=0; i < 4 ; i++){
		if(buffer[i] != elf_magic_bytes[i]){
			printf("Given binary is not an ELF\n");
			fclose(fp);
			return EXIT_FAILURE;
		}
	}
	printf("Given binary is an ELF\n");
	

	rewind(fp);

	elf_header_parser(fp);
	const char* get_machine_name(uint16_t e_machine);
	fclose(fp);
  	


	return 0;
}
