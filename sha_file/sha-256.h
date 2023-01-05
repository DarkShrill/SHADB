//
// Created by Edoardo Papa on 2019-09-05.
//

#ifndef SHADBPROJECT_SHA_256_H
#define SHADBPROJECT_SHA_256_H

#include <stddef.h>


#define operation_256_1(x) (rolRight(x, 7) ^ rolRight(x,18) ^  ((x & 0xFFFFFFFF) >> 3))
#define operation_256_2(x) (rolRight(x,17) ^ rolRight(x,19) ^  ((x & 0xFFFFFFFF) >> 10))

#define operation_256_3(x) (rolRight(x, 2) ^ rolRight(x,13) ^ rolRight(x,22))
#define operation_256_4(x) (rolRight(x, 6) ^ rolRight(x,11) ^ rolRight(x,25))

#define operation_256_5(x,y,z) ((x & y) | (z & (x | y)))
#define operation_256_6(x,y,z) (z ^ (x & (y ^ z)))


static const unsigned char sha256_padding[64] =
{
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};



typedef struct
{
    unsigned long total[2];          /* < numero di byte processati  */
    unsigned long state[8];          /* < stato del digest  */
    unsigned char buffer[64];        /* < blocco di dati in elaborazione */
}sha256_context;


void sha256_init( sha256_context *ctx );
void sha256_free( sha256_context *ctx );
void sha256_starts( sha256_context *ctx );
void sha256_update( sha256_context *ctx, unsigned char *input,size_t ilen );
void sha256_finish( sha256_context *ctx, char output[32] );
void sha256_process( sha256_context *ctx, unsigned char data[64] );
void sha256( unsigned char *input, size_t ilen,char output[32] );
void sha256_clear( sha256_context * context, size_t n );




/************************************************       PER TEST       ************************************************/


unsigned char sha256_self_test(unsigned char index);



#endif //SHADBPROJECT_SHA_256_H
