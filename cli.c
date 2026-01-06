
#include <stdio.h>
#include <stdlib.h>
#define BUFFER_SIZE 50

int main(int argc,char* argv[]){
	FILE* fp;
	unsigned char buffer[BUFFER_SIZE];
	size_t bytes_read;
	
	if(argc != 3){
		printf("elf-inspector [HEADER] [BINARY]\n");
		return 1;
	}
        
	fp = fopen(*argv[2],"rb");
	if (fp == NULL){
		fprintf(stderr,"Error opening file %s",*argv[2]);
		return EXIT_FAILURE;
	}

	bytes_read = fread(buffer,1,BUFFER_SIZE,fp);
	
	fclose(*argv[2]);
  	




	if(*argv[1] == "--all" || *argv[1] == "-a"){

	}




	return 0;
}
