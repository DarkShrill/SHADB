//
// Created by Edoardo Papa on 2019-09-05.
//

#ifndef SHADBPROJECT_COMMON_H
#define SHADBPROJECT_COMMON_H


unsigned long get_manipulate_integer_big_endian(unsigned char data[64],unsigned short number);
void put_manipulate_integer_big_endian(unsigned char * data, unsigned long value ,unsigned long index);
unsigned long long get_manipulate_64_integer_big_endian(unsigned char data[64],unsigned short number);
void put_manipulate_64_integer_big_endian(unsigned char * data, unsigned long long value ,unsigned long index);
unsigned long rolLeft(unsigned long data, unsigned char num);
unsigned long rolRight(unsigned long data, unsigned char num);
unsigned long long rolRight_64bit(unsigned long long data, unsigned char num);

#endif //SHADBPROJECT_COMMON_H
