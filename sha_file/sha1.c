//
// Created by Edoardo Papa on 2019-09-02.
//

#include <string.h>
#include <stdio.h>
#include "sha1.h"
#include "common.h"


/**
 * Inseirisco all'interno della struttura tutti 0x00
 * @param context struttura SHA1
 * @param n grandezza del buffer.
 */
void sha1_clear( sha1_context * context, size_t n )
{
    memset(context,0x00,n);
}

/**
 * Inserisco all'interno della struttura tutti 0x00
 * @param context struttura dell'SHA1
 */
void sha1_init( sha1_context * context )
{
    memset( context, 0, sizeof( sha1_context ) );
}

/**
 * Verifico che la struttura non sia nulla e in caso negativo, inserisco al
 *  suo inteno tutti 0x00
 * @param context struttura dell'SHA1
 */
void sha1_free( sha1_context * context )
{
    if( context == NULL )
        return;

    sha1_clear( context , sizeof( sha1_context ) );
}

/**
 * SetUp del SHA1
 * @param context struttura dell'SHA1
 */
void sha1_starts( sha1_context * context )
{
    context->total[0] = 0;
    context->total[1] = 0;

    context->state[0] = 0x67452301;
    context->state[1] = 0xEFCDAB89;
    context->state[2] = 0x98BADCFE;
    context->state[3] = 0x10325476;
    context->state[4] = 0xC3D2E1F0;
}



/**
 * Trasformazione da 16 32bit words in 8 32bit words.
 * @param number
 * @return
 */
unsigned long transform_from_sixteen_to_eighty(unsigned long * W,unsigned char number)
{
    unsigned long temp;
    temp = 0;

    return (temp = W[( number -  3 ) & 0x0F] ^ W[( number - 8 ) & 0x0F] ^ W[( number - 14 ) & 0x0F] ^ W[ number & 0x0F],W[number & 0x0F] = rolLeft(
            temp, 1));
}

/**
 * Calcolo dell' SHA1
 * @param context struttura dell' SHA1
 * @param data blocco di dati in elaborazione
 */
void sha1_process( sha1_context * context, unsigned char data[64] )
{
    unsigned long W[16], A, B, C, D, E,constant;

    W[0] = get_manipulate_integer_big_endian(data,  0);
    W[1] = get_manipulate_integer_big_endian(data,  4);
    W[2] = get_manipulate_integer_big_endian(data,  8);
    W[3] = get_manipulate_integer_big_endian(data,  12);
    W[4] = get_manipulate_integer_big_endian(data,  16);
    W[5] = get_manipulate_integer_big_endian(data,  20);
    W[6] = get_manipulate_integer_big_endian(data,  24);
    W[7] = get_manipulate_integer_big_endian(data,  28);
    W[8] = get_manipulate_integer_big_endian(data,  32);
    W[9] = get_manipulate_integer_big_endian(data,  36);
    W[10] = get_manipulate_integer_big_endian(data, 40);
    W[11] = get_manipulate_integer_big_endian(data, 44);
    W[12] = get_manipulate_integer_big_endian(data, 48);
    W[13] = get_manipulate_integer_big_endian(data, 52);
    W[14] = get_manipulate_integer_big_endian(data, 56);
    W[15] = get_manipulate_integer_big_endian(data, 60);


    A = context->state[0];
    B = context->state[1];
    C = context->state[2];
    D = context->state[3];
    E = context->state[4];


//----------------------------------------------   PRIMA PARTE   ----------------------------------------------

    constant = 0x5A827999;

    E += rolLeft(A, 5) + operation_1(B,C,D) + constant + W[0];
    B= rolLeft(B, 30);

    D += rolLeft(E, 5) + operation_1(A,B,C) + constant + W[1];
    A= rolLeft(A, 30);

    C += rolLeft(D, 5) + operation_1(E,A,B) + constant + W[2];
    E= rolLeft(E, 30);

    B += rolLeft(C, 5) + operation_1(D,E,A) + constant + W[3];
    D= rolLeft(D, 30);

    A += rolLeft(B, 5) + operation_1(C,D,E) + constant + W[4];
    C= rolLeft(C, 30);


    E += rolLeft(A, 5) + operation_1(B,C,D) + constant + W[5];
    B= rolLeft(B, 30);

    D += rolLeft(E, 5) + operation_1(A,B,C) + constant + W[6];
    A= rolLeft(A, 30);

    C += rolLeft(D, 5) + operation_1(E,A,B) + constant + W[7];
    E= rolLeft(E, 30);

    B += rolLeft(C, 5) + operation_1(D,E,A) + constant + W[8];
    D= rolLeft(D, 30);

    A += rolLeft(B, 5) + operation_1(C,D,E) + constant + W[9];
    C= rolLeft(C, 30);


    E += rolLeft(A, 5) + operation_1(B,C,D) + constant + W[10];
    B= rolLeft(B, 30);

    D += rolLeft(E, 5) + operation_1(A,B,C) + constant + W[11];
    A= rolLeft(A, 30);

    C += rolLeft(D, 5) + operation_1(E,A,B) + constant + W[12];
    E= rolLeft(E, 30);

    B += rolLeft(C, 5) + operation_1(D,E,A) + constant + W[13];
    D= rolLeft(D, 30);

    A += rolLeft(B, 5) + operation_1(C,D,E) + constant + W[14];
    C= rolLeft(C, 30);


    E += rolLeft(A, 5) + operation_1(B,C,D) + constant + W[15];
    B= rolLeft(B, 30);

    D += rolLeft(E, 5) + operation_1(A,B,C) + constant + transform_from_sixteen_to_eighty(W,16) ;
    A= rolLeft(A, 30);

    C += rolLeft(D, 5) + operation_1(E,A,B) + constant + transform_from_sixteen_to_eighty(W,17);
    E= rolLeft(E, 30);

    B += rolLeft(C, 5) + operation_1(D,E,A) + constant + transform_from_sixteen_to_eighty(W,18);
    D= rolLeft(D, 30);

    A += rolLeft(B, 5) + operation_1(C,D,E) + constant + transform_from_sixteen_to_eighty(W,19);
    C= rolLeft(C, 30);


//----------------------------------------------   SECONDA PARTE   ----------------------------------------------


    constant = 0x6ED9EBA1;


    E += rolLeft(A, 5) + operation_2(B,C,D) + constant + transform_from_sixteen_to_eighty(W,20);
    B= rolLeft(B, 30);

    D += rolLeft(E, 5) + operation_2(A,B,C) + constant + transform_from_sixteen_to_eighty(W,21) ;
    A= rolLeft(A, 30);

    C += rolLeft(D, 5) + operation_2(E,A,B) + constant + transform_from_sixteen_to_eighty(W,22);
    E= rolLeft(E, 30);

    B += rolLeft(C, 5) + operation_2(D,E,A) + constant + transform_from_sixteen_to_eighty(W,23);
    D= rolLeft(D, 30);

    A += rolLeft(B, 5) + operation_2(C,D,E) + constant + transform_from_sixteen_to_eighty(W,24);
    C= rolLeft(C, 30);


    E += rolLeft(A, 5) + operation_2(B,C,D) + constant + transform_from_sixteen_to_eighty(W,25) ;
    B= rolLeft(B, 30);

    D += rolLeft(E, 5) + operation_2(A,B,C) + constant + transform_from_sixteen_to_eighty(W,26) ;
    A= rolLeft(A, 30);

    C += rolLeft(D, 5) + operation_2(E,A,B) + constant + transform_from_sixteen_to_eighty(W,27);
    E= rolLeft(E, 30);

    B += rolLeft(C, 5) + operation_2(D,E,A) + constant + transform_from_sixteen_to_eighty(W,28);
    D= rolLeft(D, 30);

    A += rolLeft(B, 5) + operation_2(C,D,E) + constant + transform_from_sixteen_to_eighty(W,29);
    C= rolLeft(C, 30);


    E += rolLeft(A, 5) + operation_2(B,C,D) + constant + transform_from_sixteen_to_eighty(W,30);
    B= rolLeft(B, 30);

    D += rolLeft(E, 5) + operation_2(A,B,C) + constant + transform_from_sixteen_to_eighty(W,31) ;
    A= rolLeft(A, 30);

    C += rolLeft(D, 5) + operation_2(E,A,B) + constant + transform_from_sixteen_to_eighty(W,32);
    E= rolLeft(E, 30);

    B += rolLeft(C, 5) + operation_2(D,E,A) + constant + transform_from_sixteen_to_eighty(W,33);
    D= rolLeft(D, 30);

    A += rolLeft(B, 5) + operation_2(C,D,E) + constant + transform_from_sixteen_to_eighty(W,34);
    C= rolLeft(C, 30);


    E += rolLeft(A, 5) + operation_2(B,C,D) + constant + transform_from_sixteen_to_eighty(W,35);
    B= rolLeft(B, 30);

    D += rolLeft(E, 5) + operation_2(A,B,C) + constant + transform_from_sixteen_to_eighty(W,36) ;
    A= rolLeft(A, 30);

    C += rolLeft(D, 5) + operation_2(E,A,B) + constant + transform_from_sixteen_to_eighty(W,37);
    E= rolLeft(E, 30);

    B += rolLeft(C, 5) + operation_2(D,E,A) + constant + transform_from_sixteen_to_eighty(W,38);
    D= rolLeft(D, 30);

    A += rolLeft(B, 5) + operation_2(C,D,E) + constant + transform_from_sixteen_to_eighty(W,39);
    C= rolLeft(C, 30);



//----------------------------------------------   TERZA PARTE   ----------------------------------------------



    constant = 0x8F1BBCDC;


    E += rolLeft(A, 5) + operation_3(B,C,D) + constant + transform_from_sixteen_to_eighty(W,40);
    B= rolLeft(B, 30);

    D += rolLeft(E, 5) + operation_3(A,B,C) + constant + transform_from_sixteen_to_eighty(W,41) ;
    A= rolLeft(A, 30);

    C += rolLeft(D, 5) + operation_3(E,A,B) + constant + transform_from_sixteen_to_eighty(W,42);
    E= rolLeft(E, 30);

    B += rolLeft(C, 5) + operation_3(D,E,A) + constant + transform_from_sixteen_to_eighty(W,43);
    D= rolLeft(D, 30);

    A += rolLeft(B, 5) + operation_3(C,D,E) + constant + transform_from_sixteen_to_eighty(W,44);
    C= rolLeft(C, 30);


    E += rolLeft(A, 5) + operation_3(B,C,D) + constant + transform_from_sixteen_to_eighty(W,45) ;
    B= rolLeft(B, 30);

    D += rolLeft(E, 5) + operation_3(A,B,C) + constant + transform_from_sixteen_to_eighty(W,46) ;
    A= rolLeft(A, 30);

    C += rolLeft(D, 5) + operation_3(E,A,B) + constant + transform_from_sixteen_to_eighty(W,47);
    E= rolLeft(E, 30);

    B += rolLeft(C, 5) + operation_3(D,E,A) + constant + transform_from_sixteen_to_eighty(W,48);
    D= rolLeft(D, 30);

    A += rolLeft(B, 5) + operation_3(C,D,E) + constant + transform_from_sixteen_to_eighty(W,49);
    C= rolLeft(C, 30);


    E += rolLeft(A, 5) + operation_3(B,C,D) + constant + transform_from_sixteen_to_eighty(W,50);
    B= rolLeft(B, 30);

    D += rolLeft(E, 5) + operation_3(A,B,C) + constant + transform_from_sixteen_to_eighty(W,51) ;
    A= rolLeft(A, 30);

    C += rolLeft(D, 5) + operation_3(E,A,B) + constant + transform_from_sixteen_to_eighty(W,52);
    E= rolLeft(E, 30);

    B += rolLeft(C, 5) + operation_3(D,E,A) + constant + transform_from_sixteen_to_eighty(W,53);
    D= rolLeft(D, 30);

    A += rolLeft(B, 5) + operation_3(C,D,E) + constant + transform_from_sixteen_to_eighty(W,54);
    C= rolLeft(C, 30);


    E += rolLeft(A, 5) + operation_3(B,C,D) + constant + transform_from_sixteen_to_eighty(W,55);
    B= rolLeft(B, 30);

    D += rolLeft(E, 5) + operation_3(A,B,C) + constant + transform_from_sixteen_to_eighty(W,56) ;
    A= rolLeft(A, 30);

    C += rolLeft(D, 5) + operation_3(E,A,B) + constant + transform_from_sixteen_to_eighty(W,57);
    E= rolLeft(E, 30);

    B += rolLeft(C, 5) + operation_3(D,E,A) + constant + transform_from_sixteen_to_eighty(W,58);
    D= rolLeft(D, 30);

    A += rolLeft(B, 5) + operation_3(C,D,E) + constant + transform_from_sixteen_to_eighty(W,59);
    C= rolLeft(C, 30);



//----------------------------------------------   QUARTA PARTE   ----------------------------------------------



    constant = 0xCA62C1D6;


    E += rolLeft(A, 5) + operation_4(B,C,D) + constant + transform_from_sixteen_to_eighty(W,60);
    B= rolLeft(B, 30);

    D += rolLeft(E, 5) + operation_4(A,B,C) + constant + transform_from_sixteen_to_eighty(W,61) ;
    A= rolLeft(A, 30);

    C += rolLeft(D, 5) + operation_4(E,A,B) + constant + transform_from_sixteen_to_eighty(W,62);
    E= rolLeft(E, 30);

    B += rolLeft(C, 5) + operation_4(D,E,A) + constant + transform_from_sixteen_to_eighty(W,63);
    D= rolLeft(D, 30);

    A += rolLeft(B, 5) + operation_4(C,D,E) + constant + transform_from_sixteen_to_eighty(W,64);
    C= rolLeft(C, 30);


    E += rolLeft(A, 5) + operation_4(B,C,D) + constant + transform_from_sixteen_to_eighty(W,65) ;
    B= rolLeft(B, 30);

    D += rolLeft(E, 5) + operation_4(A,B,C) + constant + transform_from_sixteen_to_eighty(W,66) ;
    A= rolLeft(A, 30);

    C += rolLeft(D, 5) + operation_4(E,A,B) + constant + transform_from_sixteen_to_eighty(W,67);
    E= rolLeft(E, 30);

    B += rolLeft(C, 5) + operation_4(D,E,A) + constant + transform_from_sixteen_to_eighty(W,68);
    D= rolLeft(D, 30);

    A += rolLeft(B, 5) + operation_4(C,D,E) + constant + transform_from_sixteen_to_eighty(W,69);
    C= rolLeft(C, 30);


    E += rolLeft(A, 5) + operation_4(B,C,D) + constant + transform_from_sixteen_to_eighty(W,70);
    B= rolLeft(B, 30);

    D += rolLeft(E, 5) + operation_4(A,B,C) + constant + transform_from_sixteen_to_eighty(W,71) ;
    A= rolLeft(A, 30);

    C += rolLeft(D, 5) + operation_4(E,A,B) + constant + transform_from_sixteen_to_eighty(W,72);
    E= rolLeft(E, 30);

    B += rolLeft(C, 5) + operation_4(D,E,A) + constant + transform_from_sixteen_to_eighty(W,73);
    D= rolLeft(D, 30);

    A += rolLeft(B, 5) + operation_4(C,D,E) + constant + transform_from_sixteen_to_eighty(W,74);
    C= rolLeft(C, 30);


    E += rolLeft(A, 5) + operation_4(B,C,D) + constant + transform_from_sixteen_to_eighty(W,75);
    B= rolLeft(B, 30);

    D += rolLeft(E, 5) + operation_4(A,B,C) + constant + transform_from_sixteen_to_eighty(W,76) ;
    A= rolLeft(A, 30);

    C += rolLeft(D, 5) + operation_4(E,A,B) + constant + transform_from_sixteen_to_eighty(W,77);
    E= rolLeft(E, 30);

    B += rolLeft(C, 5) + operation_4(D,E,A) + constant + transform_from_sixteen_to_eighty(W,78);
    D= rolLeft(D, 30);

    A += rolLeft(B, 5) + operation_4(C,D,E) + constant + transform_from_sixteen_to_eighty(W,79);
    C= rolLeft(C, 30);


//----------------------------------------------   END   ----------------------------------------------

    context->state[0] += A;
    context->state[1] += B;
    context->state[2] += C;
    context->state[3] += D;
    context->state[4] += E;
}

/**
 * Calcolo dell' SHA1
 * @param context struttura dell'SHA1
 * @param input buffer dati
 * @param ilen lunghezza del buffer
 */
void sha1_update( sha1_context * context, unsigned char *input, size_t ilen )
{
size_t fill;
unsigned long left;

    if( ilen == 0 )
        return;

    left = context->total[0] & 0x3F;
    fill = 64 - left;

    context->total[0] += (unsigned long) ilen;
    context->total[0] &= 0xFFFFFFFF;

    if( context->total[0] < (unsigned long) ilen )
        context->total[1]++;

    if( left && ilen >= fill )
    {
        memcpy((context->buffer + left), input, fill );
        sha1_process( context, context->buffer );
        input += fill;
        ilen  -= fill;
        left = 0;
    }

    while( ilen >= 64 )
    {
        sha1_process( context, input );
        input += 64;
        ilen  -= 64;
    }

    if( ilen > 0 )
        memcpy((context->buffer + left), input, ilen );
}


/**
 * Calcolo finale del digest
 * @param context struttura dell'SHA1
 * @param output result
 */
void sha1_finish( sha1_context * context,char output[20] )
{
unsigned long last, padn;
unsigned long high, low;
unsigned char msglen[8];

    high = ( context->total[0] >> 29 )
           | ( context->total[1] <<  3 );
    low  = ( context->total[0] <<  3 );

    put_manipulate_integer_big_endian( msglen,high, 0 );
    put_manipulate_integer_big_endian( msglen,low , 4 );

    last = context->total[0] & 0x3F;
    padn = ( last < 56 ) ? ( 56 - last ) : ( 120 - last );

    sha1_update( context, sha1_padding, padn );
    sha1_update( context, msglen, 8 );


    put_manipulate_integer_big_endian(output,context->state[0] , 0);
    put_manipulate_integer_big_endian(output,context->state[1] , 4);
    put_manipulate_integer_big_endian(output,context->state[2] , 8);
    put_manipulate_integer_big_endian(output,context->state[3] , 12);
    put_manipulate_integer_big_endian(output,context->state[4] , 16);

}

/**
 * Funzione generale per calcolare l'SHA1
 * @param input da decodificare
 * @param ilen lunghezza dell'input
 * @param output digest di uscita
 */
void sha1(unsigned char *input, size_t ilen, char output[20] )
{
sha1_context ctx;

    sha1_init( &ctx );
    sha1_starts( &ctx );
    sha1_update( &ctx, input, ilen );
    sha1_finish( &ctx, output );
    sha1_free( &ctx );

}


/************************************************       PER TEST       ************************************************/



static const unsigned char sha1_test_buf[2][57] =
{
    { "abc" },
    { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" }
};

static const int sha1_test_buflen[3] =
{
    3, 56
};

static const unsigned char sha1_test_sum[2][20] =
{
    { 0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A, 0xBA, 0x3E,
      0x25, 0x71, 0x78, 0x50, 0xC2, 0x6C, 0x9C, 0xD0, 0xD8, 0x9D },
    { 0x84, 0x98, 0x3E, 0x44, 0x1C, 0x3B, 0xD2, 0x6E, 0xBA, 0xAE,
      0x4A, 0xA1, 0xF9, 0x51, 0x29, 0xE5, 0xE5, 0x46, 0x70, 0xF1 }
};


unsigned char sha_self_test(unsigned char index)
{

unsigned char value_to_return = -1;
unsigned char sha1sum[20];
sha1_context context;



    sha1_init(&context);

    printf("Hai appena eseguito      SHA-1 test #%d: ", index);

    sha1_starts(&context);

    sha1_update(&context, sha1_test_buf[index], sha1_test_buflen[index]);

    sha1_finish(&context, sha1sum);


    if (memcmp(sha1sum, sha1_test_sum[index], 20) != 0)
    {
        // Non sono uguali, quindi qualcosa è andato storto.
        printf("failed\n");
        value_to_return = 0;
        goto END;
    }

    value_to_return = 1;

    printf("passed\n");

END:
    sha1_free( &context );

    return value_to_return;
}
