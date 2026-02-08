#include "elf_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
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

void print_usage(char* exec_name){
	printf("\n\033[1;33mUsage:\033[0m %s [OPTIONS] -f <file>\n\n",exec_name);
    printf("\033[1;32mOptions:\033[0m\n");
    printf("  -f, --file <file>    Path to the ELF binary to inspect (Required)\n");
    printf("  -a, --all            Display ALL headers (ELF + Program)\n");
    printf("  -e, --eh             Parse and display the ELF Header\n");
    printf("  -p, --ph             Parse and display the Program Header Table\n");
    printf("  -h, --help           Display this help menu\n\n");
    printf("\033[1;34mExample:\033[0m\n");
    printf("  %s -f /bin/ls -eh\n\n", exec_name);
}

int main(int argc,char* argv[]){

	print_banner();

	int opt;
	char* filename = NULL;
	int do_elf_header = 0;
	int do_prog_header = 0;
	int show_help = 0;

	static struct option long_options[] = {
        {"file",    required_argument, 0, 'f'},
        {"headers", no_argument,       0, 'h'},
        {"eh",      no_argument,       0, 'e'},
        {"ph",      no_argument,       0, 'p'},
        {"help",    no_argument,       0, '?'},
        {"all",		no_argument,	   0,  'a'},
        {0, 0, 0, 0}
    };

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

	int header_parsed = 0;
	int option_index = 0;
	while((opt = getopt_long(argc, argv, "f:epah", long_options, &option_index)) != -1){
		switch(opt){
			case 'f':
				filename = optarg;
				break;
			case 'a':
				do_elf_header = 1;
				do_prog_header =1;
				break;
			case 'e':
				do_elf_header = 1;
				break;
			case 'p':
				do_prog_header = 1;
				break;
			default:
				show_help = 1;
				break;
		}
	}

	if (show_help || filename == NULL){
		print_usage(argv[0]);
		return (filename == NULL && !show_help) ? EXIT_FAILURE : EXIT_SUCCESS;
	}

	fp = fopen(filename,"rb");
	if(!fp){
		perror("Error opening file\n");
		return EXIT_FAILURE;
	}

	Elf64_Ehdr my_header = elf_header_parser(fp);

	if(do_elf_header){
		display_elf_header(fp,my_header);
	}

	if(do_prog_header){
		program_header(fp,my_header);
	}

	fclose(fp);
	return 0;
}
