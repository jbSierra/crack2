#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "md5.h"

const int PASS_LEN = 20;        // Maximum any password will be
const int HASH_LEN = 33;        // Length of MD5 hash strings


// Given a target plaintext word, use it to try to find
// a matching hash in the hashFile.
// Get this function working first!
char * tryWord(char * plaintext, char * hashFilename)
{
    char line[HASH_LEN];
    char *nl = strchr(plaintext, '\n'); 
    if (nl) 
    {
        *nl = '\0'; 
    }
    // Hash the plaintext
    char *hash = md5(plaintext, strlen(plaintext));
    // Open the hash file
    FILE *file = fopen(hashFilename, "r");
    // Loop through the hash file, one line at a time.
    while (fgets(line, sizeof(line), file))
    {
        // trim newline 
        char *nl = strchr(line, '\n'); 
            if (nl) 
            {
            *nl = '\0'; 
            }
        // Attempt to match the hash from the file to the
        // hash of the plaintext.
        if (strcmp(line, hash) == 0)
        {
            fclose(file); 
            return hash;  
        }
    }
    fclose(file); 
    free(hash);   
    
    return NULL; 
}


int main(int argc, char *argv[])
{
    if (argc < 3) 
    {
        fprintf(stderr, "Usage: %s hash_file dict_file\n", argv[0]);
        exit(1);
    }


    // Open the dictionary file for reading.
    FILE *dictionary = fopen(argv[2], "r");
    int cracked = 0;
    char word[PASS_LEN + 1];

    // For each dictionary word, pass it to tryWord, which
    // will attempt to match it against the hashes in the hash_file.
    while (fgets(word, sizeof(word), dictionary))
    {
        // trim newline
        char *n2 = strchr(word, '\n'); 
            if (n2) 
            {
            *n2 = '\0'; 
            }

        char *match = tryWord(word, argv[1]);
        if (match != NULL)
        {
            cracked ++;
            // If we got a match, display the hash and the word. For example:
            printf("%s %s \n", match, word);
            // Free up any malloc'd memory?
            free(match);
        
        }
    }

    // Close the dictionary file.
    fclose(dictionary);
    // Display the number of hashes that were cracked.
    printf("%d hashes cracked\n", cracked);    
   
}

