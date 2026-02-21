#ifndef ELF_PARSER_H
#define ELF_PARSER_H

#include <elf.h>
#include <stdio.h>

Elf64_Ehdr elf_header_parser(FILE* fp);
const char* get_machine_name(uint16_t e_machine);
void program_header(FILE* fp,Elf64_Ehdr header);
void display_elf_header(FILE* fp,Elf64_Ehdr header);
void display_security_overview(FILE* fp,Elf64_Ehdr header,Elf64_Shdr *sec_header,char* mmap_base);
const char* check_pie(Elf64_Ehdr *header);
void check_stack_canary(Elf64_Ehdr* my_header,char* mmap_base);
void check_NX(Elf64_Ehdr* header,char* mmap_base);
void check_fortify(Elf64_Ehdr* header,char* mmap_base);

#endif 
