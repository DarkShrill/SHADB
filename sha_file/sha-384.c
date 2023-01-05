//
// Created by Edoardo Papa on 2019-09-07.
//

#include "sha-384.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"


#define transform_from_sixteen_to_sixtyfour(t)              \
(                                                           \
    W[t] = operation_384_2(W[t -  2]) + W[t -  7] +         \
           operation_384_1(W[t - 15]) + W[t - 16]           \
)

static const unsigned long long K[80] =
{
        UL64(0x428A2F98D728AE22),  UL64(0x7137449123EF65CD),
        UL64(0xB5C0FBCFEC4D3B2F),  UL64(0xE9B5DBA58189DBBC),
        UL64(0x3956C25BF348B538),  UL64(0x59F111F1B605D019),
        UL64(0x923F82A4AF194F9B),  UL64(0xAB1C5ED5DA6D8118),
        UL64(0xD807AA98A3030242),  UL64(0x12835B0145706FBE),
        UL64(0x243185BE4EE4B28C),  UL64(0x550C7DC3D5FFB4E2),
        UL64(0x72BE5D74F27B896F),  UL64(0x80DEB1FE3B1696B1),
        UL64(0x9BDC06A725C71235),  UL64(0xC19BF174CF692694),
        UL64(0xE49B69C19EF14AD2),  UL64(0xEFBE4786384F25E3),
        UL64(0x0FC19DC68B8CD5B5),  UL64(0x240CA1CC77AC9C65),
        UL64(0x2DE92C6F592B0275),  UL64(0x4A7484AA6EA6E483),
        UL64(0x5CB0A9DCBD41FBD4),  UL64(0x76F988DA831153B5),
        UL64(0x983E5152EE66DFAB),  UL64(0xA831C66D2DB43210),
        UL64(0xB00327C898FB213F),  UL64(0xBF597FC7BEEF0EE4),
        UL64(0xC6E00BF33DA88FC2),  UL64(0xD5A79147930AA725),
        UL64(0x06CA6351E003826F),  UL64(0x142929670A0E6E70),
        UL64(0x27B70A8546D22FFC),  UL64(0x2E1B21385C26C926),
        UL64(0x4D2C6DFC5AC42AED),  UL64(0x53380D139D95B3DF),
        UL64(0x650A73548BAF63DE),  UL64(0x766A0ABB3C77B2A8),
        UL64(0x81C2C92E47EDAEE6),  UL64(0x92722C851482353B),
        UL64(0xA2BFE8A14CF10364),  UL64(0xA81A664BBC423001),
        UL64(0xC24B8B70D0F89791),  UL64(0xC76C51A30654BE30),
        UL64(0xD192E819D6EF5218),  UL64(0xD69906245565A910),
        UL64(0xF40E35855771202A),  UL64(0x106AA07032BBD1B8),
        UL64(0x19A4C116B8D2D0C8),  UL64(0x1E376C085141AB53),
        UL64(0x2748774CDF8EEB99),  UL64(0x34B0BCB5E19B48A8),
        UL64(0x391C0CB3C5C95A63),  UL64(0x4ED8AA4AE3418ACB),
        UL64(0x5B9CCA4F7763E373),  UL64(0x682E6FF3D6B2B8A3),
        UL64(0x748F82EE5DEFB2FC),  UL64(0x78A5636F43172F60),
        UL64(0x84C87814A1F0AB72),  UL64(0x8CC702081A6439EC),
        UL64(0x90BEFFFA23631E28),  UL64(0xA4506CEBDE82BDE9),
        UL64(0xBEF9A3F7B2C67915),  UL64(0xC67178F2E372532B),
        UL64(0xCA273ECEEA26619C),  UL64(0xD186B8C721C0C207),
        UL64(0xEADA7DD6CDE0EB1E),  UL64(0xF57D4F7FEE6ED178),
        UL64(0x06F067AA72176FBA),  UL64(0x0A637DC5A2C898A6),
        UL64(0x113F9804BEF90DAE),  UL64(0x1B710B35131C471B),
        UL64(0x28DB77F523047D84),  UL64(0x32CAAB7B40C72493),
        UL64(0x3C9EBE0A15C9BEBC),  UL64(0x431D67C49C100D4C),
        UL64(0x4CC5D4BECB3E42B6),  UL64(0x597F299CFC657E2A),
        UL64(0x5FCB6FAB3AD6FAEC),  UL64(0x6C44198C4A475817)
};





/**
 * Inseirisco all'interno della struttura tutti 0x00
 * @param context struttura SHA384
 * @param n grandezza del buffer.
 */
void sha384_clear( sha384_context * context, size_t n )
{
    memset(context,0x00,n);
}

/**
 * Inserisco all'interno della struttura tutti 0x00
 * @param context struttura dell'SHA384
 */
void sha384_init( sha384_context * context )
{
    memset( context, 0x00 , sizeof( sha384_context ) );
}

/**
 * Verifico che la struttura non sia nulla e in caso negativo, inserisco al
 *  suo inteno tutti 0x00
 * @param context struttura dell'SHA384
 */
void sha384_free( sha384_context * context )
{
    if( context  == NULL )
        return;

    sha384_clear( context , sizeof( sha384_context ) );
}

/**
 * SetUp del SHA384
 * @param context struttura dell'SHA384
 */
void sha384_starts( sha384_context * context )
{
    context->total[0] = 0;
    context->total[1] = 0;

    /* SHA-384 */
    context->state[0] = UL64(0xCBBB9D5DC1059ED8);
    context->state[1] = UL64(0x629A292A367CD507);
    context->state[2] = UL64(0x9159015A3070DD17);
    context->state[3] = UL64(0x152FECD8F70E5939);
    context->state[4] = UL64(0x67332667FFC00B31);
    context->state[5] = UL64(0x8EB44A8768581511);
    context->state[6] = UL64(0xDB0C2E0D64F98FA7);
    context->state[7] = UL64(0x47B5481DBEFA4FA4);
 }


/**
 * Calcolo dell' SHA384
 * @param context struttura dell' SHA384
 * @param data blocco di dati in elaborazione
 */
void sha384_process( sha384_context * context, const unsigned char data[128] )
{
int i;
unsigned long long temp1, temp2, W[80];
unsigned long long A[8];

    for( i = 0; i < 16; i++ )
    {
        W[i] = get_manipulate_64_integer_big_endian(data, i << 3 );
    }

    for( ; i < 80; i++ )
    {
        transform_from_sixteen_to_sixtyfour(i);
    }

    A[0] = context->state[0];
    A[1] = context->state[1];
    A[2] = context->state[2];
    A[3] = context->state[3];
    A[4] = context->state[4];
    A[5] = context->state[5];
    A[6] = context->state[6];
    A[7] = context->state[7];



    for(i = 0; i < 80; i+=8)
    {
        temp1 = A[7] + operation_384_4(A[4]) + operation_384_6(A[4],A[5],A[6]) + K[i+0] + W[i+0];
        temp2 = operation_384_3(A[0]) + operation_384_5(A[0],A[1],A[2]);
        A[3] += temp1;
        A[7] = temp1 + temp2;

        temp1 = A[6] + operation_384_4(A[3]) + operation_384_6(A[3],A[4],A[5]) + K[i+1] + W[i+1];
        temp2 = operation_384_3(A[7]) + operation_384_5(A[7],A[0],A[1]);
        A[2] += temp1;
        A[6] = temp1 + temp2;

        temp1 = A[5] + operation_384_4(A[2]) + operation_384_6(A[2],A[3],A[4]) + K[i+2] + W[i+2];
        temp2 = operation_384_3(A[6]) + operation_384_5(A[6],A[7],A[0]);
        A[1] += temp1;
        A[5] = temp1 + temp2;

        temp1 = A[4] + operation_384_4(A[1]) + operation_384_6(A[1],A[2],A[3]) + K[i+3] + W[i+3];
        temp2 = operation_384_3(A[5]) + operation_384_5(A[5],A[6],A[7]);
        A[0] += temp1;
        A[4] = temp1 + temp2;

        temp1 = A[3] + operation_384_4(A[0]) + operation_384_6(A[0],A[1],A[2]) + K[i+4] + W[i+4];
        temp2 = operation_384_3(A[4]) + operation_384_5(A[4],A[5],A[6]);
        A[7] += temp1;
        A[3] = temp1 + temp2;

        temp1 = A[2] + operation_384_4(A[7]) + operation_384_6(A[7],A[0],A[1]) + K[i+5] + W[i+5];
        temp2 = operation_384_3(A[3]) + operation_384_5(A[3],A[4],A[5]);
        A[6] += temp1;
        A[2] = temp1 + temp2;

        temp1 = A[1] + operation_384_4(A[6]) + operation_384_6(A[6],A[7],A[0]) + K[i+6] + W[i+6];
        temp2 = operation_384_3(A[2]) + operation_384_5(A[2],A[3],A[4]);
        A[5] += temp1;
        A[1] = temp1 + temp2;

        temp1 = A[0] + operation_384_4(A[5]) + operation_384_6(A[5],A[6],A[7]) + K[i+7] + W[i+7];
        temp2 = operation_384_3(A[1]) + operation_384_5(A[1],A[2],A[3]);
        A[4] += temp1;
        A[0] = temp1 + temp2;
    }

    context->state[0] += A[0];
    context->state[1] += A[1];
    context->state[2] += A[2];
    context->state[3] += A[3];
    context->state[4] += A[4];
    context->state[5] += A[5];
    context->state[6] += A[6];
    context->state[7] += A[7];


}

/**
 * Calcolo dell' SHA384
 * @param context struttura dell'SHA384
 * @param input buffer dati
 * @param ilen lunghezza del buffer
 */
void sha384_update( sha384_context * context, const unsigned char *input,size_t ilen )
{
size_t fill;
unsigned int left;

    if( ilen == 0 )
        return;

    left = (unsigned int) (context->total[0] & 0x7F);
    fill = 128 - left;

    context->total[0] += (uint64_t) ilen;

    if( context->total[0] < (uint64_t) ilen )
        context->total[1]++;

    if( left && ilen >= fill )
    {
        memcpy((context->buffer + left), input, fill );
        sha384_process( context, context->buffer );
        input += fill;
        ilen  -= fill;
        left = 0;
    }

    while( ilen >= 128 )
    {
        sha384_process( context, input );
        input += 128;
        ilen  -= 128;
    }

    if( ilen > 0 )
        memcpy((context->buffer + left), input, ilen );
}


/**
 * Calcolo finale del digest
 * @param context struttura dell'SHA384
 * @param output result
 */
void sha384_finish( sha384_context * context,char output[64] )
{
size_t last, padn;
unsigned long long high, low;
unsigned char msglen[16];

    high = ( context->total[0] >> 61 ) | ( context->total[1] <<  3 );
    low  = ( context->total[0] <<  3 );

    put_manipulate_64_integer_big_endian(msglen, high , 0 );
    put_manipulate_64_integer_big_endian(msglen, low  , 8 );

    last = (size_t)( context->total[0] & 0x7F );
    padn = ( last < 112 ) ? ( 112 - last ) : ( 240 - last );

    sha384_update( context, sha384_padding, padn );
    sha384_update( context, msglen, 16 );

    put_manipulate_64_integer_big_endian( output,context->state[0],  0 );
    put_manipulate_64_integer_big_endian( output,context->state[1],  8 );
    put_manipulate_64_integer_big_endian( output,context->state[2], 16 );
    put_manipulate_64_integer_big_endian( output,context->state[3], 24 );
    put_manipulate_64_integer_big_endian( output,context->state[4], 32 );
    put_manipulate_64_integer_big_endian( output,context->state[5], 40 );

}

/**
 * Funzione generale per calcolare l'SHA384
 * @param input da decodificare
 * @param ilen lunghezza dell'input
 * @param output digest di uscita
 */
void sha384(unsigned char *input, size_t ilen,char output[64])
{
sha384_context ctx;

    sha384_init( &ctx );
    sha384_starts( &ctx);
    sha384_update( &ctx, input, ilen );
    sha384_finish( &ctx, output );
    sha384_free( &ctx );
}


/************************************************       PER TEST       ************************************************/


static const unsigned char sha384_test_buf[2][113] =
{
    { "abc" },
    { "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
      "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu" }
};

static const int sha384_test_buflen[2] =
{
    3, 112
};

static const unsigned char sha384_test_sum[2][64] =
{
    { 0xCB, 0x00, 0x75, 0x3F, 0x45, 0xA3, 0x5E, 0x8B,
      0xB5, 0xA0, 0x3D, 0x69, 0x9A, 0xC6, 0x50, 0x07,
      0x27, 0x2C, 0x32, 0xAB, 0x0E, 0xDE, 0xD1, 0x63,
      0x1A, 0x8B, 0x60, 0x5A, 0x43, 0xFF, 0x5B, 0xED,
      0x80, 0x86, 0x07, 0x2B, 0xA1, 0xE7, 0xCC, 0x23,
      0x58, 0xBA, 0xEC, 0xA1, 0x34, 0xC8, 0x25, 0xA7 },
    { 0x09, 0x33, 0x0C, 0x33, 0xF7, 0x11, 0x47, 0xE8,
      0x3D, 0x19, 0x2F, 0xC7, 0x82, 0xCD, 0x1B, 0x47,
      0x53, 0x11, 0x1B, 0x17, 0x3B, 0x3B, 0x05, 0xD2,
      0x2F, 0xA0, 0x80, 0x86, 0xE3, 0xB0, 0xF7, 0x12,
      0xFC, 0xC7, 0xC7, 0x1A, 0x55, 0x7E, 0x2D, 0xB9,
      0x66, 0xC3, 0xE9, 0xFA, 0x91, 0x74, 0x60, 0x39 }

};




unsigned char sha384_self_test(unsigned char index)
{

unsigned char value_to_return = -1;
unsigned char sha384sum[48];
sha384_context context;


    sha384_init(&context);

    printf("Hai appena eseguito      SHA-384 test #%d: ", index);

    sha384_starts(&context);

    sha384_update(&context, sha384_test_buf[index], sha384_test_buflen[index]);

    sha384_finish(&context, sha384sum);


    if (memcmp(sha384sum, sha384_test_sum[index], 48) != 0)
    {
        // Non sono uguali, quindi qualcosa è andato storto.
        printf("failed\n");
        value_to_return = 0;
        goto END;
    }

    value_to_return = 1;

    printf("passed\n");

END:
    sha384_free( &context );

    return value_to_return;
}
