#ifndef ELF_PARSER_H
#define ELF_PARSER_H

#include <elf.h>
#include <stdio.h>

void elf_header_parser(FILE* fp);
const char* get_machine_name(uint16_t e_machine);


#endif 
