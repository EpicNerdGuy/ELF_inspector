#include "elf_parser.h"
#include <elf.h>
#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#define COLOR_RED     "\x1b[31m"
#define COLOR_GREEN   "\x1b[32m"
#define COLOR_RESET   "\x1b[0m"
#define COLOR_BOLD    "\x1b[1m"


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

	printf("Machine: %s\t\n", get_machine_name(header.e_machine));
	printf("Entry point address: 0x%lx\t\n", header.e_entry);
	printf("Start of program headers: %lu\t\n",header.e_phoff);
	printf("Start of section headers: %lu\t\n",header.e_shoff);
}


void check_NX(Elf64_Ehdr* header,char* mmap_base){
	Elf64_Phdr *phdr_table = (Elf64_Phdr *)(mmap_base + header->e_phoff);

	for(int i = 0; i < header->e_phnum; i++){

		if(phdr_table[i].p_type == PT_GNU_STACK){

			if(phdr_table[i].p_flags & PF_X){
				printf("NX: "COLOR_RED "\t\tDISABLED" COLOR_RESET"\n");
				return;
			} else{
				printf("NX: "COLOR_GREEN "\t\tENABLED" COLOR_RESET"\n");
				return;
			}
		}
	}
	printf("NX: "COLOR_RED "\t\tDISABLED" COLOR_RESET"\n");
}

void check_RELRO(Elf64_Ehdr *header, char* mmap_base){
	int has_relro = 0;
	int is_full_relro = 0;
	Elf64_Phdr *phdr_table = (Elf64_Phdr *)(mmap_base + header->e_phoff);
	Elf64_Shdr *shdr_table = (Elf64_Shdr *)(mmap_base + header->e_shoff);

	for(int i = 0; i < header->e_phnum; i++){

		if(phdr_table[i].p_type == PT_GNU_RELRO){
			has_relro = 1;
		}
	}

	for(int i = 0; i < header->e_shnum; i++){
		Elf64_Shdr *sec_header = &shdr_table[i];

		if(sec_header->sh_type == SHT_DYNAMIC){
			Elf64_Dyn *dyn = (Elf64_Dyn *)(mmap_base + sec_header->sh_offset);
			int entries = sec_header->sh_size/sizeof(Elf64_Dyn);

			for(int j = 0; j < entries; j++){
				if (dyn[j].d_tag == DT_FLAGS && (dyn[j].d_un.d_val & DF_BIND_NOW)) {
					is_full_relro = 1;
				}
				if (dyn[j].d_tag == DT_FLAGS_1 && (dyn[j].d_un.d_val & DF_1_NOW)) {
					is_full_relro = 1;
				}
			}
		}
	}

	if(!has_relro){
		printf("RELRO:		DISASBLED\n");
	}
	else if(is_full_relro){
		printf("RELRO:		FULL RELRO\n");
	}
	else{
		printf("RELRO:		PARTIAL RELRO");
	}

}



void check_stack_canary(Elf64_Ehdr *header, char* mmap_base) {
    
    Elf64_Shdr *shdr_table = (Elf64_Shdr *)(mmap_base + header->e_shoff);
    
   
    for (int i = 0; i < header->e_shnum; i++) {
        Elf64_Shdr *sec_header = &shdr_table[i];
        
        
        if (sec_header->sh_type == SHT_DYNSYM) {
            Elf64_Shdr *strtab_shdr = &shdr_table[sec_header->sh_link];
            char *strtab_ptr = (char *)(mmap_base + strtab_shdr->sh_offset);
            Elf64_Sym *sym = (Elf64_Sym *)(mmap_base + sec_header->sh_offset);
            
            int num_symbols = sec_header->sh_size / sec_header->sh_entsize;

            for (int j = 0; j < num_symbols; j++) {
                char* symbol_name = strtab_ptr + sym[j].st_name;

                if (strcmp(symbol_name, "__stack_chk_fail") == 0) {
                    printf("STACK CANARY: "COLOR_GREEN "\tFOUND" COLOR_RESET"\n");
                    return; 
                }
            }
        }
    }
    
    
    printf("STACK CANARY: "COLOR_RED "\tNOT FOUND" COLOR_RESET"\n");
}

void check_fortify(Elf64_Ehdr *header, char *mmap_base){
	
	Elf64_Shdr *shdr_table = (Elf64_Shdr *)(mmap_base + header->e_shoff);
	int fortified = 0;

	for(int i = 0; i < header->e_shnum; i++){
		
		if(shdr_table[i].sh_type == SHT_DYNSYM){

			Elf64_Sym *sym_table = (Elf64_Sym *)(mmap_base + shdr_table[i].sh_offset);
			char *str_table = (char *)(mmap_base + shdr_table[shdr_table[i].sh_link].sh_offset);
			int num_symbols = shdr_table[i].sh_size / sizeof(Elf64_Sym);

			for(int j = 0; j < num_symbols; j++){
				char *sym_name = str_table + sym_table[j].st_name;
				if (strstr(sym_name, "_chk") != NULL) {
                    if(!fortified){
						printf("FORTIFY: "COLOR_GREEN "\tENABLED" COLOR_RESET"\n");
						fortified = 1;
					}
					printf("[+] Found fortified function: %s\n", sym_name);                    
                }

			}
		}
	}
	if(!fortified){
		printf("FORTIFY: "COLOR_RED "\tDISABLED" COLOR_RESET"\n");
	}
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
	return (header -> e_type == ET_DYN) ? COLOR_GREEN "ENABLED" COLOR_RESET : COLOR_RED "DISABLED" COLOR_RESET;
}

void display_security_overview(FILE* fp,Elf64_Ehdr header,Elf64_Shdr *sec_header,char* mmap_base){
	printf("\x1b[1;32m");
	printf("\n[+] Security Overview:\n");
	printf("----------------\n");
	printf("\x1b[0m\n");
	printf("\x1b[1;32m");
	printf("\x1b[0m");
	const char* PIE;
	PIE = check_pie(&header);
	printf("PIE:	\t%s\n",PIE);
	check_RELRO(&header, mmap_base);
	check_stack_canary(&header,mmap_base);
	check_NX(&header,mmap_base);
	check_fortify(&header, mmap_base);
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


 


