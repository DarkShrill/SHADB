//
// Created by Edoardo Papa on 2019-09-11.
//

#ifndef SHADBPROJECT_MANAGER_H
#define SHADBPROJECT_MANAGER_H

#include "general.h"


void manage_command_received(enum TYPE_OF_OPTION type, struct digit_arguments * arg);
void add_command(struct digit_arguments * arg);
void find_command(struct digit_arguments * arg);
unsigned char find_digest(char * path,char * digest);

#endif //SHADBPROJECT_MANAGER_H
