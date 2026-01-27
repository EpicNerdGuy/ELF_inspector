#include "elf_parser.h"
#include <stdio.h>
#include <stdlib.h>
#define BUFFER_SIZE 4

void print_banner() {
    // \x1b[1;32m: Bold Green
    printf("\x1b[1;32m");
    printf("  ______ _      ______   _____ _   _  _____ _____  ______ _____ _______ ____  _____  \n");
    printf(" |  ____| |    |  ____| |_   _| \\ | |/ ____|  __ \\|  ____/ ____|__   __/ __ \\|  __ \\ \n");
    printf(" | |__  | |    | |__      | | |  \\| | (___ | |__) | |__ | |       | | | |  | | |__) |\n");
    printf(" |  __| | |    |  __|     | | | . ` |\\___ \\|  ___/|  __|| |       | | | |  | |  _  / \n");
    printf(" | |____| |____| |       _| |_| |\\  |____) | |    | |___| |____   | | | |__| | | \\ \\ \n");
    printf(" |______|______|_|      |_____|_| \\_|_____/|_|    |______\\_____|  |_|  \\____/|_|  \\_\\\n");
    
    // Subheading
    printf("\n");
    printf("          >> Advanced Binary Analysis & ELF Structure Inspector <<\n");
    printf("                      v1.0 | Reverse Engineering Tool\n");
    printf("=====================================================================================\n");
    printf("\x1b[0m\n"); // Reset color
}

int main(int argc,char* argv[]){
	Elf64_Ehdr header;
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

	print_banner();

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

	rewind(fp);

	elf_header_parser(fp);
	const char* get_machine_name(uint16_t e_machine);
	program_header(fp,header);
	fclose(fp);
  	


	return 0;
}
