//
// Created by Edoardo Papa on 2019-09-09.
//

#include "general.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//#include <stdbool.h>
#include "stdlib.h"
#include "limits.h"
#include "manage_sha.h"


/**
 * Partendo da un PATH verifico se quel determinato file esiste. In caso negativo, lo creo.
 * @param path PATH del file.
 */
void exist_file(char * path)
{
FILE *file;

    file = fopen(path, "r");          // Apro il file in lettura

    if (file == NULL) {
        file = fopen(path, "w");
        fclose(file);
    }
    fclose(file);
}

/**
 * Partendo da un PATH analizzo quel determinato file in maniera tale da riempire la struttura (@FILE_OUT_INFO) con tutti i dati del file.
 *
 * @param path PATH del file
 * @return la struttura contenete tutte le informazioni del file.
 */
FILE_OUT_INFO analizeFile(char * path)
{
FILE *file;
char next = 0;
char *line = NULL;
ssize_t read;
size_t len;

    //exist_file(path);

    file = fopen(path, "r");          // Apro il file in lettura

    if (file == NULL)
    {
        printf("\nFILE NON PRESENTE : %s \n",path);
        fclose(file);
    }

    volatile FILE_OUT_INFO file_list;

    file_list.absolute_path = NULL;
    file_list.sha           = 0;
    file_list.digest        = NULL;
    file_list.next_element  = NULL;

    FILE_OUT_INFO *element = malloc(sizeof(FILE_OUT_INFO));

    element->absolute_path = NULL;
    element->digest = 0;
    element->sha = 0;
    element->next_element = NULL;

    while ((read = getline(&line, &len, file)) != -1)
    {
        char *token = strtok(line, "\r\n");

        if (!element) {
            printf("ERRORRE!!!!!!");
        }


        while (token != NULL)
        {
            if (strcspn(token, "/") == 0)
            {
                element->absolute_path = malloc(strlen(token) + 1);
                if (element->absolute_path == NULL)
                {
                    printf("ERRORRE");
                }
                strcpy(element->absolute_path, token);
            }
            else if (strcspn(token, "S") == 0)
            {
                for (int i = 0; i < sizeof(map) / sizeof(map[0]); i++)
                {
                    if (strcmp(token, map[i].s) == 0)
                    {
                        element->sha = map[i].sha;
                        break;
                    }
                }
            }
            else
            {
                element->digest = malloc(strlen(token) + 1);
                if (element->digest == NULL)
                {
                    printf("ERRORRE");
                }
                strcpy(element->digest, token);
                next = 1;
            }


            token = strtok(NULL, "\r\n");
        }

        if(next)
        {
            next = 0;
            if (file_list.absolute_path != NULL)
            {
                for (FILE_OUT_INFO *ptr = &file_list; ptr != NULL; ptr = ptr->next_element)
                {
                    if (ptr->next_element == NULL)
                    {
                        ptr->next_element                   = malloc(sizeof(FILE_OUT_INFO));
                        ptr->next_element->absolute_path    = element->absolute_path;
                        ptr->next_element->sha              = element->sha;
                        ptr->next_element->digest           = element->digest;
                        ptr->next_element->next_element     = element->next_element;
                        break;
                    }
                }
            }
            else
            {
                file_list.absolute_path = malloc(sizeof(char *));
                file_list.absolute_path = element->absolute_path;
                file_list.sha           = element->sha;
                file_list.digest        = element->digest;
                file_list.next_element  = element->next_element;

            }
            FILE_OUT_INFO *element = malloc(sizeof(FILE_OUT_INFO));
        }
    }

//    FILE_OUT_INFO *ptr = &file_list;
//    while (ptr != NULL) {
//        FILE_OUT_INFO *next = ptr->next_element;
//        free(ptr->absolute_path);
//        //free(ptr);
//        ptr = next;
//    }

    fclose(file);
    free(element);
    return file_list;
}

/**
 * Mi estrapolo la lunghezza del file passato come parametro formale
 * @param data dati del file
 * @return quantità dei dati
 */
unsigned long get_len_of_data(const char * data)
{
unsigned long counter_charatter = 0;

    while(*data != '\0')
    {
        counter_charatter++;
        data++;
    }

    data -= counter_charatter;
    return counter_charatter;
}



/************************************************       PER TEST       ************************************************/




void test_all_function_from__GENERAL_H(char * path)
{
/**********************************     ANALIZE FILE     **********************************/

    printf("Hai appena eseguito      analizeFile() function and the test is: ");
    char * out_temp;
    strcat(&out_temp,&path);
    out_temp[strlen(out_temp) - 6] = '\0';
    strcat(&out_temp[0],"/shadb_for_test.out");
    if(analizeFile(out_temp).digest == NULL)
    {
        printf("                                  failed\n");
    }
    printf("                                  passed\n");

/**********************************     GET LEN OF DATA     *******************************/

    printf("Hai appena eseguito      get_len_of_data() function and the test is: ");
    if(get_len_of_data("CIAO") != 4)
    {
        printf("                              failed\n");
    }
    printf("                              passed\n");



}


