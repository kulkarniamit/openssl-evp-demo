#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#define ERR_EVP_CIPHER_INIT -1
#define ERR_EVP_CIPHER_UPDATE -2
#define ERR_EVP_CIPHER_FINAL -3
#define ERR_EVP_CTX_NEW -4

#define AES_256_KEY_SIZE 32
#define AES_BLOCK_SIZE 16
#define BUFSIZE 1024

typedef struct _cipher_params_t{
    unsigned char *key;
    unsigned char *iv;
    unsigned int encrypt;
    const EVP_CIPHER *cipher_type;
}cipher_params_t;

void cleanup(cipher_params_t *params, FILE *ifp, FILE *ofp, int rc){
    free(params);
    fclose(ifp);
    fclose(ofp);
    exit(rc);
}

void file_encrypt_decrypt(cipher_params_t *params, FILE *ifp, FILE *ofp){
    /* Allow enough space in output buffer for additional block */
    int cipher_block_size = EVP_CIPHER_block_size(params->cipher_type);
    unsigned char in_buf[BUFSIZE], out_buf[BUFSIZE + cipher_block_size];

    int num_bytes_read, out_len;
    EVP_CIPHER_CTX *ctx;

    ctx = EVP_CIPHER_CTX_new();
    if(ctx == NULL){
        fprintf(stderr, "ERROR: EVP_CIPHER_CTX_new failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        cleanup(params, ifp, ofp, ERR_EVP_CTX_NEW);
    }

    /* Don't set key or IV right away; we want to check lengths */
    if(!EVP_CipherInit_ex(ctx, params->cipher_type, NULL, NULL, NULL, params->encrypt)){
        fprintf(stderr, "ERROR: EVP_CipherInit_ex failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        cleanup(params, ifp, ofp, ERR_EVP_CIPHER_INIT);
    }

    OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == AES_256_KEY_SIZE);
    OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == AES_BLOCK_SIZE);

    /* Now we can set key and IV */
    if(!EVP_CipherInit_ex(ctx, NULL, NULL, params->key, params->iv, params->encrypt)){
        fprintf(stderr, "ERROR: EVP_CipherInit_ex failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        EVP_CIPHER_CTX_cleanup(ctx);
        cleanup(params, ifp, ofp, ERR_EVP_CIPHER_INIT);
    }

    while(1){
        // Read in data in blocks until EOF. Update the ciphering with each read.
        num_bytes_read = fread(in_buf, sizeof(unsigned char), BUFSIZE, ifp);
        if (ferror(ifp)){
            fprintf(stderr, "ERROR: fread error: %s\n", strerror(errno));
            EVP_CIPHER_CTX_cleanup(ctx);
            cleanup(params, ifp, ofp, errno);
        }
        if(!EVP_CipherUpdate(ctx, out_buf, &out_len, in_buf, num_bytes_read)){
            fprintf(stderr, "ERROR: EVP_CipherUpdate failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
            EVP_CIPHER_CTX_cleanup(ctx);
            cleanup(params, ifp, ofp, ERR_EVP_CIPHER_UPDATE);
        }
        fwrite(out_buf, sizeof(unsigned char), out_len, ofp);
        if (ferror(ofp)) {
            fprintf(stderr, "ERROR: fwrite error: %s\n", strerror(errno));
            EVP_CIPHER_CTX_cleanup(ctx);
            cleanup(params, ifp, ofp, errno);
        }
        if (num_bytes_read < BUFSIZE) {
            /* Reached End of file */
            break;
        }
    }

    /* Now cipher the final block and write it out to file */
    if(!EVP_CipherFinal_ex(ctx, out_buf, &out_len)){
        fprintf(stderr, "ERROR: EVP_CipherFinal_ex failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        EVP_CIPHER_CTX_cleanup(ctx);
        cleanup(params, ifp, ofp, ERR_EVP_CIPHER_FINAL);
    }
    fwrite(out_buf, sizeof(unsigned char), out_len, ofp);
    if (ferror(ofp)) {
        fprintf(stderr, "ERROR: fwrite error: %s\n", strerror(errno));
        EVP_CIPHER_CTX_cleanup(ctx);
        cleanup(params, ifp, ofp, errno);
    }
    EVP_CIPHER_CTX_cleanup(ctx);
}

int main(int argc, char *argv[]) {
    FILE *f_input, *f_enc, *f_dec;

    /* Make sure user provides the input file */
    if (argc != 2) {
        printf("Usage: %s /path/to/file\n", argv[0]);
        return -1;
    }

    cipher_params_t *params = (cipher_params_t *)malloc(sizeof(cipher_params_t));
    if (!params) {
        /* Unable to allocate memory on heap*/
        fprintf(stderr, "ERROR: malloc error: %s\n", strerror(errno));
        return errno;
    }

    /* Key to use for encrpytion and decryption */
    unsigned char key[AES_256_KEY_SIZE];

    /* Initialization Vector */
    unsigned char iv[AES_BLOCK_SIZE];

    /* Generate cryptographically strong pseudo-random bytes for key and IV */
    if (!RAND_bytes(key, sizeof(key)) || !RAND_bytes(iv, sizeof(iv))) {
        /* OpenSSL reports a failure, act accordingly */
        fprintf(stderr, "ERROR: RAND_bytes error: %s\n", strerror(errno));
        return errno;
    }
    params->key = key;
    params->iv = iv;

    /* Indicate that we want to encrypt */
    params->encrypt = 1;

    /* Set the cipher type you want for encryption-decryption */
    params->cipher_type = EVP_aes_256_cbc();

    /* Open the input file for reading in binary ("rb" mode) */
    f_input = fopen(argv[1], "rb");
    if (!f_input) {
        /* Unable to open file for reading */
        fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
        return errno;
    }

    /* Open and truncate file to zero length or create ciphertext file for writing */
    f_enc = fopen("encrypted_file", "wb");
    if (!f_enc) {
        /* Unable to open file for writing */
        fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
        return errno;
    }

    /* Encrypt the given file */
    file_encrypt_decrypt(params, f_input, f_enc);

    /* Encryption done, close the file descriptors */
    fclose(f_input);
    fclose(f_enc);

    /* Decrypt the file */
    /* Indicate that we want to decrypt */
    params->encrypt = 0;

    /* Open the encrypted file for reading in binary ("rb" mode) */
    f_input = fopen("encrypted_file", "rb");
    if (!f_input) {
        /* Unable to open file for reading */
        fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
        return errno;
    }

    /* Open and truncate file to zero length or create decrypted file for writing */
    f_dec = fopen("decrypted_file", "wb");
    if (!f_dec) {
        /* Unable to open file for writing */
        fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
        return errno;
    }

    /* Decrypt the given file */
    file_encrypt_decrypt(params, f_input, f_dec);

    /* Close the open file descriptors */
    fclose(f_input);
    fclose(f_dec);

    /* Free the memory allocated to our structure */
    free(params);

    return 0;
}
