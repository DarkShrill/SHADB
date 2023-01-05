//
// Created by Edoardo Papa on 2019-09-12.
//

#ifndef SHADBPROJECT_RWFILE_H
#define SHADBPROJECT_RWFILE_H

#include <stdio.h>
#include "general.h"


void write_new_element_to_file(struct digit_arguments arg,char * digest, unsigned long len);
char * ReadFile(char *path);



/************************************************       PER TEST       ************************************************/

void test_all_function_from__RWFILE_H(char * path_to_analize, char* path);

#endif //SHADBPROJECT_RWFILE_H
