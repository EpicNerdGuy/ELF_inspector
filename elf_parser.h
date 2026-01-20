#ifndef ELF_PARSER_H
#define ELF_PARSER_H

#include <elf.h>
#include <stdio.h>

void elf_header_parser(FILE* fp);
void check_endian(FILE* fp);


#endif 
