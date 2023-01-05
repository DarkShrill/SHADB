//
// Created by Edoardo Papa on 2019-09-11.
//

#ifndef SHADBPROJECT_MANAGE_SHA_H
#define SHADBPROJECT_MANAGE_SHA_H

#include "general.h"



unsigned char get_SHA_needBuffer_size( enum TYPE_SHA sha);
char * calculate_SHA(char * analize_file , enum TYPE_SHA sha,unsigned char needBuffer_size);
char * get_string_of_sha(enum TYPE_SHA sha);
unsigned char is_same_digest(FILE_OUT_INFO *list,char * digest,unsigned long len);
enum TYPE_OF_OPTION get_type_of_option_from_string(char * type);
void get_string_of_digest(char * out,unsigned long len);


/************************************************       PER TEST       ************************************************/



void test_all_function_from__MANAGE_SHA_H(char * path);

#endif //SHADBPROJECT_MANAGE_SHA_H
