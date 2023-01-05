//
// Created by Edoardo Papa on 2019-09-11.
//

#include <stdlib.h>
#include "manage_sha.h"
#include "sha_file/sha1.h"
#include "sha_file/sha-256.h"
#include "sha_file/sha-224.h"
#include "sha_file/sha-384.h"
#include "sha_file/sha-512.h"
#include "string.h"
#include "stdio.h"
#include "rwfile.h"

/**
 * Mi trovo, a seconda del SHA che si vuole utilizzare, la lunghezza del buffer che andrà a contenere il DIGEST
 * @param sha SHA da utilizzare
 * @return lunghezza
 */
unsigned char get_SHA_needBuffer_size( enum TYPE_SHA sha)
{
unsigned char temp = 0;


    switch(sha)
    {
        case SHA1 :
        {
            temp = 20;
            break;
        }
        case SHA224 :
        {
            temp = 28;
            break;
        }
        case SHA256 :
        {
            temp = 32;
            break;
        }
        case SHA384 :
        {
            temp = 48;
            break;
        }
        case SHA512 :
        {
            temp = 64;
            break;
        }
    }

    return temp;
}

/**
 * Questa funzione permette di calcolare l'SHA di un file di input.
 * @param analize_file file da analizzare
 * @param sha tipo di SHA da utilizzare
 * @param needBuffer_size lunghezza del buffer a seconda dello SHA da utilizzare
 * @return puntatore al contenuto del DIGEST calcolato.
 */
char * calculate_SHA(char * analize_file , enum TYPE_SHA sha,unsigned char needBuffer_size)
{
//char out[needBuffer_size];
char * out = 0;
char * in_pointer;// = NULL;
size_t len;
unsigned long i = 0;

    //APRO IL FILE, LO LEGGO E MI SAVO TUTTO SU UN ARRAY.
    //in_pointer = (char*)malloc(sizeof(char*));

    out = malloc(sizeof(char *) * needBuffer_size);



    in_pointer = ReadFile(analize_file);
    len = strlen(in_pointer);


//    in_pointer[len] = '\0';

//    unsigned char in[len];
//
//    while(*in_pointer != '\0')
//    {
//        in[i] = *in_pointer;
//        in_pointer++;
//        i++;
//    }


    switch(sha)
    {
        case SHA1 :
        {
            sha1(in_pointer, len,out);
            break;
        }
        case SHA224 :
        {
            sha224(in_pointer, len,out);
            break;
        }
        case SHA256 :
        {
            sha256(in_pointer, len,out);
            break;
        }
        case SHA384 :
        {
            sha384(in_pointer, len,out);
            break;
        }
        case SHA512 :
        {
            sha512(in_pointer, len,out);
            break;
        }
    }
    //free(in_pointer);
    return out;
}


/**
 * Questa funzione permette di ritornare il nome dell' SHA passato ( stringa )
 * @param sha SHA selezionato
 * @return puntatore alla stringa.
 */
char * get_string_of_sha(enum TYPE_SHA sha)
{
    switch(sha)
    {
        case SHA1:
        {
            return "SHA1";
            break;
        }
        case SHA224:
        {
            return "SHA224";
            break;
        }
        case SHA256:
        {
            return "SHA256";
            break;
        }
        case SHA384:
        {
            return "SHA384";
            break;
        }
        case SHA512:
        {
            return "SHA512";
            break;
        }
    }
}

/**
 * Questa funzione permette di "mostrare a video" la "stringa" del DIGEST calcolato.
 * @param out i dati del DIGEST
 * @param len lunghezza dei dati a seconda dello SHA
 */
void get_string_of_digest(char * out,unsigned long len)
{
    for(unsigned char c1 = 0; c1 < len; c1++)
    {
        if((out[c1] & 0xFF ) <= 0x0F)
            printf("0%x",out[c1]&0xFF);
        else
            printf("%x",out[c1]&0xFF);
    }
    printf("\n");
}

/**
 * Questa funzione permette di verificare se due digest sono uguali o no.
 * @param list struttura contenente com'è formato il "repository"
 * @param digest DIGEST da cercare
 * @param len lunghezza del DIGEST
 * @return 0 se ho trovato nel repository il digest passato come parametro formale, altrmineti 1.
 */
unsigned char is_same_digest(FILE_OUT_INFO *list,char * digest,unsigned long len)
{
unsigned int same_count = 0;

    for(unsigned char i = 0; i < len; i++)
    {
        unsigned char data = 0;
        unsigned char data2 = 0;
        data = digest[i] & 0xF;
        data2 = (digest[i] & 0xF0)>>4 ;

        // Le operazioni successive, servono per potermi travore in ASCII i dati (0 ... 9 e a..f)
        data += 48;
        data2 += 48;

        if((data < 66)&&(data > 57))
            data+=7+32;

        if((data2 < 66)&&(data2 > 57))
            data2+=7+32;


        char dig = 0;
        char dig2 = 0;

        dig = list->digest[i*2];

        dig2 = list->digest[(i*2) + 1];

        if((data == dig2) && (data2 == dig))
        {
            same_count++;
        }
    }

    if(same_count == len)
    {
        return 0;
    }
    else
    {
        return 1;
    }
}

/**
 * Questa funzione permette di trovare, a seconda della stringa passata come parametro formale, il tipo di opzione selezionata.
 * @param type stringa
 * @return opzione
 */
enum TYPE_OF_OPTION get_type_of_option_from_string(char * type)
{
    if((strcmp(type, "ADD") == 0) || (strcmp(type, "add") == 0))
    {
        return ADD;
    }
    if((strcmp(type, "FIND") == 0) || (strcmp(type, "find") == 0))
    {
        return FIND;
    }

    return ERROR;
}


/************************************************       PER TEST       ************************************************/



void test_all_function_from__MANAGE_SHA_H(char * path)
{

    /**********************************     GET SHA NEEDBUFFER SIZE     **********************************/

    printf("Hai appena eseguito      get_SHA_needBuffer_size() function and the test is: ");

    if((get_SHA_needBuffer_size(SHA1) != 20) || (get_SHA_needBuffer_size(SHA224) != 28) || (get_SHA_needBuffer_size(SHA256) != 32) || (get_SHA_needBuffer_size(SHA384) != 48) || (get_SHA_needBuffer_size(SHA512) != 64))
    {
        printf("                      failed\n");
    }
    printf("                      passed\n");

    /**********************************     CALCULATE SHA     **********************************/

    printf("Hai appena eseguito      calculate_SHA() function and the test is: ");

    //char * out_temp;
    //strcpy(out_temp,path);
    path[strlen(path) - 18] = '\0';
    strcat(&path[0],"analize_file_for_test.in");

    char out_sha1[20];
    char out_sha224[28];
    char out_sha256[32];
    char out_sha384[48];
    char out_sha512[64];


    sha1("ciao, come stai?",16,out_sha1);
    sha224("ciao, come stai?",16,out_sha224);
    sha256("ciao, come stai?",16,out_sha256);
    sha384("ciao, come stai?",16,out_sha384);
    sha512("ciao, come stai?",16,out_sha512);

    if((memcmp(calculate_SHA(path,SHA1,20),out_sha1,20) != 0)&&\
       (memcmp(calculate_SHA(path,SHA224,28),out_sha224,28) != 0)&&\
       (memcmp(calculate_SHA(path,SHA256,32),out_sha256,32) != 0)&&\
       (memcmp(calculate_SHA(path,SHA384,48),out_sha384,48) != 0)&&\
       (memcmp(calculate_SHA(path,SHA512,64),out_sha512,64) != 0))
    {
        printf("                                failed\n");
    }
    printf("                                passed\n");

    /**********************************     GET STRING OF SHA SHA     *****************************/

    printf("Hai appena eseguito      get_string_of_sha() function and the test is: ");


    if((strcmp(get_string_of_sha(SHA1),"SHA1") != 0) || (strcmp(get_string_of_sha(SHA224),"SHA224") != 0) ||\
        (strcmp(get_string_of_sha(SHA256),"SHA256") != 0) ||(strcmp(get_string_of_sha(SHA384),"SHA384") != 0) ||\
        (strcmp(get_string_of_sha(SHA512),"SHA512") != 0))
    {
        printf("                            failed\n");
    }
    printf("                            passed\n");

    /**********************************     IS SAME DIGEST     *****************************/

    printf("Hai appena eseguito      is_same_digest() function and the test is: ");

    unsigned char err = 0;

    FILE_OUT_INFO * file = malloc(sizeof(FILE_OUT_INFO));
    file->digest        = (char*)"fb2c8005824a86b4fde89824c62d20107fd550c1";
    file->sha           = SHA1;
    file->absolute_path = "/pippo.txt";

    if(is_same_digest(file,calculate_SHA(path,SHA1,20),20) != 0)
        err |= 1;

    FILE_OUT_INFO * file_SHA224 = malloc(sizeof(FILE_OUT_INFO));
    file_SHA224->digest        = (char*)"8614756975f04af8b74cd176f5cfe4734319348a088ff90d23f453a9";
    file_SHA224->sha           = SHA224;
    file_SHA224->absolute_path = "/pippo.txt";

    if(is_same_digest(file_SHA224,calculate_SHA(path,SHA224,28),28) != 0)
        err |= 1;

    FILE_OUT_INFO * file_SHA256 = malloc(sizeof(FILE_OUT_INFO));
    file_SHA256->digest        = (char*)"12a309d4a6538d7d4e1ee9fde8d5093240a5b5b958389664b2115fc0e25b0c2a";
    file_SHA256->sha           = SHA256;
    file_SHA256->absolute_path = "/pippo.txt";

    if(is_same_digest(file_SHA256,calculate_SHA(path,SHA256,32),32) != 0)
        err |= 1;

    FILE_OUT_INFO * file_SHA384 = malloc(sizeof(FILE_OUT_INFO));
    file_SHA384->digest        = (char*)"624d1fa15e5c5ed27bbceb6b371c0b7a15a1c1595533af7f571dc31cc7657e6b7fadd4db8391cb0a76e3cbf818aa76bd";
    file_SHA384->sha           = SHA384;
    file_SHA384->absolute_path = "/pippo.txt";

    if(is_same_digest(file_SHA384,calculate_SHA(path,SHA384,48),48) != 0)
        err |= 1;

    FILE_OUT_INFO * file_SHA512 = malloc(sizeof(FILE_OUT_INFO));
    file_SHA512->digest        = (char*)"b4875e9036814359351b247d05d78434549455ed0223a66dabd47f100ee469980cc90cf56fe5519501952672caad4bbf44b056764657d188ced4a29222d32453";
    file_SHA512->sha           = SHA512;
    file_SHA512->absolute_path = "/pippo.txt";

    if(is_same_digest(file_SHA512,calculate_SHA(path,SHA512,64),64) != 0)
        err |= 1;

    if(err != 0)
    {
        printf("                               failed\n");
    }
    printf("                               passed\n");

    free(file);
    free(file_SHA224);
    free(file_SHA256);
    free(file_SHA384);
    free(file_SHA512);

    /**********************************     GET TYPE OF OPTION FROM STRING     *****************************/

    printf("Hai appena eseguito      get_type_of_option_from_string() function and the test is: ");


    if((get_type_of_option_from_string("ADD") != ADD) || (get_type_of_option_from_string("add") != ADD)||\
       (get_type_of_option_from_string("FIND") != FIND) || (get_type_of_option_from_string("find") != FIND))
    {
        printf("               failed\n");
    }
    printf("               passed\n");


}