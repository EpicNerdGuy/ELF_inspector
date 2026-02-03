#include "elf_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#define BUFFER_SIZE 4
const char* prog_name = "ELF INSPECTOR";

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

void print_usage(char* exec_name){
	printf("\n\033[1;33mUsage:\033[0m %s [OPTIONS] -f <file>\n\n",exec_name);
    printf("\033[1;32mOptions:\033[0m\n");
    printf("  -f, --file <file>    Path to the ELF binary to inspect (Required)\n");
    printf("  -e, --eh             Parse and display the ELF Header\n");
    printf("  -p, --ph             Parse and display the Program Header Table\n");
    printf("  -h, --help           Display this help menu\n\n");
    printf("\033[1;34mExample:\033[0m\n");
    printf("  %s -f /bin/ls -eh\n\n", prog_name);
}

int main(int argc,char* argv[]){
	int opt;
	static struct option long_options[] = {
		{"file",required_argument,0,'f'},
		{"eh",no_argument,0,'e'},
		{"ph",no_argument,0,'p'},
		{0,0,0,0}
	};
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
/*
	if(argc != 2){
		printf("elf-inspector [BINARY]\n");
		return 1;
	}
*/
	int header_parsed = 0;
	int option_index = 0;
	Elf64_Ehdr my_header;
	while((opt = getopt_long(argc, argv, "f:eph", long_options, &option_index)) != -1){
		switch(opt){
			case 'h':
				print_usage(argv[1]);
				break;
			case 'f':
				fp = fopen(optarg,"rb");
				if (fp == NULL){
					fprintf(stderr,"Error opening file %s",argv[1]);
					exit(EXIT_FAILURE);
				}
				break;
			case 'e':
				if (!fp){
					fprintf(stderr, "Error: Specify file first with -f\n"); 
					break; 
				}
				my_header = elf_header_parser(fp);
				header_parsed = 1;
				const char* get_machine_name(uint16_t e_machine);
				break;
			case 'p':
				if (!header_parsed) { 
                	fprintf(stderr, "Error: Parse header (-e) before program headers (-p)\n"); 
                	break; 
            	}
				program_header(fp,my_header);
				break;
			default:
				print_usage(argv[1]);
				return 1;
		}
	}
        
	byteread = fread(buffer,1,4,fp);
	
	if(byteread < 4){
		printf("ELF file too small\n");
	}

	fclose(fp);
	return 0;
}
