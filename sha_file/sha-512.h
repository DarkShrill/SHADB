//
// Created by Edoardo Papa on 2019-09-07.
//

#ifndef SHADBPROJECT_SHA_512_H
#define SHADBPROJECT_SHA_512_H

#include <stddef.h>
#include "common.h"

static const unsigned char sha512_padding[128] =
{
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};


#define UL64(data) ((unsigned long long) data )

#define operation_512_1(x) (rolRight_64bit(x, 1) ^ rolRight_64bit(x,8) ^  ((x) >> 7))
#define operation_512_2(x) (rolRight_64bit(x,19) ^ rolRight_64bit(x,61) ^ ((x) >> 6))

#define operation_512_3(x) (rolRight_64bit(x, 28) ^ rolRight_64bit(x,34) ^ rolRight_64bit(x,39))
#define operation_512_4(x) (rolRight_64bit(x, 14) ^ rolRight_64bit(x,18) ^ rolRight_64bit(x,41))

#define operation_512_5(x,y,z) ((x & y) | (z & (x | y)))
#define operation_512_6(x,y,z) (z ^ (x & (y ^ z)))


typedef struct
{
    unsigned long long total[2];          /* < numero di byte processati  */
    unsigned long long state[8];          /* < stato del digest  */
    unsigned char buffer[128];            /* < blocco di dati in elaborazione */
}sha512_context;


void sha512_init( sha512_context * context );
void sha512_free( sha512_context * context );
void sha512_starts( sha512_context * context );
void sha512_update( sha512_context * context, unsigned char *input,size_t ilen );
void sha512_finish( sha512_context * context, char output[64] );
void sha512( unsigned char *input, size_t ilen,char output[64] );
void sha512_process( sha512_context * context, unsigned char data[128] );




/************************************************       PER TEST       ************************************************/



unsigned char sha512_self_test(unsigned char index);



#endif //SHADBPROJECT_SHA_512_H
