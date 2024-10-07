#include <string.h>
#include <stdio.h>
#include <stdlib.h>


double ioc_partition ( char*, int, int, int, int );
double* index_of_coincidence ( char*, int, int );
int ioc_check ( double*, int );
char* get_keyword ( char*, int, int* ); 
char* crack_key( char*, int, int ); 
char find_max_m( char*, int, int, int );
char shift_letter( char, int );
char* decrypt_vigenere( char*, char*, int, int );
#define N 1024 


/**
 * Vigenere Cipher Cracker
 *
 * Cameron Smith
 */
int main() 
{
    int length, keysize;
    char buf[N];
    char *keyword, *plaintext;

    printf("Enter Ciphertext: ");
    fgets(buf, N, stdin);
    buf[strcspn(buf, "\n")] = '\0';

    length = strlen(buf);
    keyword = get_keyword(buf, length, &keysize);
    printf("\nKeysize Found! - m = %d\n", keysize);
    printf("Keyword Found! - K = %s\n\n", keyword);
    plaintext = decrypt_vigenere(buf, keyword, keysize, length);
    printf("Plaintext: %s\n", plaintext);

    free(keyword);
    free(plaintext);
}

/* helper for index_of_coincidence that will find IoC for one row */
double ioc_partition( char* ciphertext, int off, int n, int m, int length) 
{
    int i;
    int *freq = calloc(26, sizeof(int));

    int index;
    for (i = 0, index = off; i < n && index < length; i++, index += m) 
        freq[ciphertext[index] - 65]++; 
    
    double ioc = 0.0;
    
    for ( i = 0; i < 26; i++ ) 
        if (freq[i] != 0.0)
            ioc += freq[i] * (freq[i] - 1);
    
    free(freq);
    return ioc / (n * (n - 1));
}

/* returns a double array of size m that equals the IoC's calculated 
 * for the ciphertext */
double* index_of_coincidence( char* ciphertext, int m, int length)
{
    double* ioc_results = malloc(sizeof(double) * m);
    
    int i;
    int n = length / m;
    int mod = length % m;

    if (n < 2) 
        fprintf(stderr, "Can't find the index of coincidence\n");

    for ( i = 0; i < m; i++ )
        if (mod > 0) {
            ioc_results[i] = ioc_partition(ciphertext, i, n + 1, m, length);
            mod--;
        }
        else 
            ioc_results[i] = ioc_partition(ciphertext, i, n, m, length);

    return ioc_results;
}

#define EXPECTED 0.065 /* Expected IoC for english alphabet*/
#define RANGE 0.010    /* Range of acceptable solutions */

/* used to check if IoC is within range, returns 1 on success, 0 on failure */
int ioc_check( double * ioc, int count )
{
    int i;
    double sum = 0.0;
    for (i = 0; i < count; i++) 
        sum += ioc[i];
    
    double avg = sum / count;

    if ( avg - EXPECTED > 0 ) {
        if ( avg - EXPECTED > RANGE )
            return 0;
    }
    else if ( EXPECTED - avg > RANGE ) 
        return 0;

    free(ioc);
    return 1;
}

/* obtains the keyword via brute force */
char* get_keyword( char* ciphertext, int length, int* size )
{
    int m = 2; // starting with size 2 and incrementing upwards

    for (;;) {
        double* ioc = index_of_coincidence(ciphertext, m, length);

        if (ioc_check( ioc, m ))
            break; // once IoC w/in range, break loop and crack the key
        
        m++;
        free(ioc);
    }
    *size = m;

    return crack_key( ciphertext, m, length);
}

/* finds the letter occurances over the given interval starting from off */
int* letter_counts( char* ciphertext, int off, int interval, int length)
{
    int* counts = calloc(26, sizeof(int));
    int index;
    for (index = off; index < length; index += interval) 
        counts[ciphertext[index] - 65] += 1;
    
    return counts;
}

/* predetermined frequencies from lookup table */
static double frequencies[] = {0.082, 0.015, 0.028, 0.043, 0.127, 0.022, 0.020, 0.061, 0.070, 0.002, 0.008, 0.040, 0.024, 0.067, 0.075, 0.019, 0.001, 0.060, 0.063, 0.091, 0.028, 0.010, 0.023, 0.001, 0.020, 0.001};

/* Finds the max M_i that will best satisfy a shift size */
char find_max_m( char* ciphertext, int off, int keysize, int length )
{
    double max = 0.0;
    char letter;
    int i, j;
    int index;

    int* counts = letter_counts(ciphertext, off, keysize, length);
   
    double curr;

    for (i = 0; i < 26; i++) {
        curr = 0;
        for (j = 0; j < 26; j++) {
            index = (i + j) % 26;
            curr += counts[index] * frequencies[j];  
        }
        curr /= keysize;
        if (curr > max) { 
            max = curr;
            letter = i + 65;
        }
    }
    free(counts);
    return letter;
}

/* cracks the ciphertext with the keysize and length of the ciphertext */
char* crack_key( char* ciphertext, int keysize, int length ) 
{
    char* keyword = malloc(sizeof(char) * keysize);
    int n = length / keysize;
    int mod = length % keysize;
    int i;

    for (i = 0; i < keysize; i++) 
        keyword[i] = find_max_m(ciphertext, i, keysize, length);

    return keyword;
}

/* shifts a letter in the positive direction */
char shift_letter( char letter, int shift)
{
    return (((letter - 65) + shift) % 26) + 97;
}

/* decrypts a vigenere cipher with ciphertext and keyword */
char* decrypt_vigenere( char* ciphertext, char* keyword, int keysize, int cipher_length )
{
    char* plaintext = malloc(sizeof(char) * cipher_length);    
    int i;
    int key_index;
    for (i = 0, key_index = 0; i < cipher_length; i++, key_index = (key_index + 1) % keysize) 
        plaintext[i] = shift_letter(ciphertext[i], 26 - (keyword[key_index] - 65));
    
    return plaintext;
}
