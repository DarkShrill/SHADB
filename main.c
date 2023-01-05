#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include "sha_file/sha1.h"
#include "sha_file/sha-256.h"
#include "sha_file/sha-224.h"
#include "sha_file/sha-384.h"
#include "sha_file/sha-512.h"
#include "general.h"
#include "string.h"
#include "manager.h"
#include "manage_sha.h"
#include "rwfile.h"

//TODO: TOGLIERE TUTTO QUELLO CHE NON SERVE E RICONTROLLARE TUTTO



const char *program_version =
        "1.0";

//#define SELF_TEST

int main(int argc, char **argv) {
    printf("         #############################################\n");
    printf("         ###                                       ###\n");
    printf("         ###     SHADB DIGEST FILE ARCHIVATION     ###\n");
    printf("         ###                                       ###\n");
    printf("         ###           Version : %s               ###\n",program_version);
    printf("         ###               created by Edoardo Papa ###\n");
    printf("         #############################################\n");
    printf("\n");
    struct digit_arguments arguments;

#ifdef SELF_TEST
unsigned char out_for_SHA1[20];
unsigned char out_for_SHA224[32 - 4];
unsigned char out_for_SHA256[32];
unsigned char out_for_SHA384[64 - 16];
unsigned char out_for_SHA512[64];
char * data_for__GENERAL;
char * data_for__MANAGE_SHA;
char * data_for__RWFILE_1;
char * data_for__RWFILE_2;

    strcpy(&data_for__GENERAL,&argv[0]);
    strcpy(&data_for__MANAGE_SHA,&argv[0]);
    strcpy(&data_for__RWFILE_1,&argv[0]);
    strcpy(&data_for__RWFILE_2,&argv[0]);

    printf("\n*******************************************************************\n\n");

//######################################       TEST SHA-1      ######################################
//    sha1_self_test(1);
//    sha1("abc",3,out_for_SHA1);

    sha_self_test(0);
    sha_self_test(1);

//######################################       TEST SHA-224      ######################################

    printf("\n*******************************************************************\n\n");
    sha224_self_test(0);
    sha224_self_test(1);

//######################################       TEST SHA-256      ######################################

    printf("\n*******************************************************************\n\n");
    sha256_self_test(0);
    sha256_self_test(1);

//######################################       TEST SHA-384      ######################################

    printf("\n*******************************************************************\n\n");
    sha384_self_test(0);
    sha384_self_test(1);

//######################################       TEST SHA-512      ######################################

    printf("\n*******************************************************************\n\n");
    sha512_self_test(0);
    sha512_self_test(1);

//######################################       TEST GENERAL FILE      ######################################

    printf("\n****************************  GENERAL  ***************************************\n\n");
    test_all_function_from__GENERAL_H(&data_for__GENERAL[0]);

//######################################       TEST MANAGE SHA FILE      ######################################

    printf("\n***************************  MANAGE_SHA  ****************************************\n\n");
    test_all_function_from__MANAGE_SHA_H(&data_for__MANAGE_SHA[0]);

//######################################       TEST RWFILE      ######################################

    printf("\n***************************  RWFILE  ****************************************\n\n");
    test_all_function_from__RWFILE_H(&data_for__RWFILE_1[0],&data_for__RWFILE_2[0]);


    exit(0);


#endif


    char * out;

    // Ho aggunto questo controllo perchè ne momento che mi trovo nella cartella contenente il file eseguibile, basterà fare ./shadb
    //      per avviare il programma, quindi per trovare il file shadb.out basterà utilizzare realpath.
    //      Nel caso in cui invece, ci troviamo ad esempio dentro C: , non riusciremo a trovare il file quindi lo estrapolo da argv[0].
    if(strlen(argv[0]) < 8)
    {
        out =  realpath("shadb.out", 0);
    }
    else
    {

        size_t len = strlen(argv[0]);

        out = malloc(sizeof(char * ) * len);

        for(unsigned long i = 0; i < len; i++)
        {
            out[i] = argv[0][i];
        }

        strcat(out,".out");

        argv[0] -= len;
    }

    arguments.type          = 0;
    arguments.output_file   = out;
    arguments.sha           = SHA1;
    arguments.analize_file  = NULL;
    arguments.type_command  = 0;

    printf("\n");

//    printf("COUNT = %d \n",argc);
//    argc = 5;
//    argv[1] = "--/Users/edoardo/Desktop/prova_scrittura2.txt";
//    argv[2] = "ADD";
//    argv[3] = "SHA256";
//    argv[4] = "/Users/edoardo/Desktop/memorabile.txt";

//    argc = 3;
//    argv[1] = "add";
//    argv[2] = "/Users/edoardo/Desktop/memorabile.txt";

    // VERIFICO IN QUALE CONDIZIONE DI DATI IN INGRESSO MI TROVO.
    switch(argc - 1)
    {
        case 2:
        {
            //HO OMESSO SIA IL FILE DI DESTINAZIONE CHE IL TIPO DI SHA //(1)
            arguments.type          = get_type_of_option_from_string(argv[1]);
            arguments.analize_file = realpath((const char *)argv[2], 0);
            break;
        }
        case 3:
        {
            //HO OMESSO IL FILE DI DESTINAZIONE OPPURE HO OMESSO SHA
            if(strstr(argv[1],"--") != NULL)//(4)
            {
                // HO OMESSO SHA
                char * c_pointer = argv[1];
                c_pointer++;
                c_pointer++;

//                arguments.output_file = malloc(sizeof(char*));
//
//                strcpy(arguments.output_file,&c_pointer[0]);

                arguments.output_file = realpath((const char *)&c_pointer[0], 0);

                arguments.type          = get_type_of_option_from_string(argv[2]);
                arguments.analize_file = realpath((const char *)argv[3], 0);

            }
            else//(2)
            {
                // HO OMESSO IL PATH
                arguments.type          = get_type_of_option_from_string(argv[1]);

                for (int i = 0; i < sizeof(map) / sizeof(map[0]); i++) {
                    if (strcmp(argv[2], map[i].s) == 0) {
                        arguments.sha = map[i].sha;
                        break;
                    }
                }

                arguments.analize_file = realpath((const char *)argv[3], 0);
            }
            break;
        }
        case 4:
        {
            //HO OMESSO IL TIPO DI SHA E HO COME PATH -d/qualcosa OPPURE --path e SHA
            if(strstr(argv[1],"--") != NULL) //(6)
            {
                // HO IL PATH --
                char * c_pointer = argv[1];
                c_pointer++;
                c_pointer++;

                arguments.output_file = realpath((const char *)&c_pointer[0], 0);

                for (int i = 0; i < sizeof(map) / sizeof(map[0]); i++) {
                    if (strcmp(argv[3], map[i].s) == 0) {
                        arguments.sha = map[i].sha;
                        break;
                    }
                }
                arguments.type          = get_type_of_option_from_string(argv[2]);
                arguments.analize_file = realpath((const char *)argv[4], 0);
            }
            else //(3)
            {
                arguments.type_command  = argv[1];
                char * c_pointer        = argv[2];

                arguments.output_file = realpath((const char *)&c_pointer[0], 0);
                arguments.type          = get_type_of_option_from_string(argv[3]);
                arguments.analize_file = realpath((const char *)argv[4], 0);
            }
            break;
        }
        case 5: //(5)
        {
            //NON HO OMESSO NULLA

            arguments.type_command      = argv[1];
            char * c_pointer        = argv[2];

            arguments.output_file = realpath((const char *)&c_pointer[0], 0);
            arguments.type              = get_type_of_option_from_string(argv[3]);

            for (int i = 0; i < sizeof(map) / sizeof(map[0]); i++) {
                if (strcmp(argv[4], map[i].s) == 0) {
                    arguments.sha = map[i].sha;
                    break;
                }
            }

            arguments.analize_file = realpath((const char *)argv[5], 0);
            break;
        }
        default:
        {
            break;
        }
    }

    manage_command_received(arguments.type,&arguments);


    printf("\n \n         ######  THE OPERATION WAS SUCCESSFUL  ######\n");

    return 0;
}
