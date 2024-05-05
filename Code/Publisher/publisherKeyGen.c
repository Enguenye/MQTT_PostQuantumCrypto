#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <oqs/oqs.h>

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define MESSAGE_LEN 100


void print_hex(const unsigned char *data, size_t length) {
    for (size_t i = 0; i < length; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

// Function to convert binary data to hexadecimal
void toHex(const uint8_t *data, size_t length, char *output) {
    for (size_t i = 0; i < length; i++) {
        sprintf(output + i * 2, "%02x", data[i]);
    }
    output[length * 2] = '\0';
}

int exportKeyToFile(const char *filename, const uint8_t *key, size_t key_length) {
    FILE *file = fopen(filename, "w");
    if (!file) return -1;

    char *hexKey = (char *)malloc(key_length * 2 + 1);
    toHex(key, key_length, hexKey);

    fprintf(file, "%s\n", hexKey);
    free(hexKey);
    fclose(file);
    return 0;
}


int main() {

    //Initializing signing keys
    OQS_STATUS rc2;
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);
    uint8_t public_key[OQS_SIG_dilithium_2_length_public_key];
    uint8_t secret_key[OQS_SIG_dilithium_2_length_secret_key];
    rc2 = OQS_SIG_dilithium_2_keypair(public_key, secret_key);
	if (rc2 != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_SIG_dilithium_2_keypair failed!\n");
		//cleanup_stack(secret_key, OQS_SIG_dilithium_2_length_secret_key);
		return OQS_ERROR;
	}

    exportKeyToFile("publicDith_key.txt", public_key, OQS_SIG_dilithium_2_length_public_key);
    exportKeyToFile("secretDith_key.txt", secret_key, OQS_SIG_dilithium_2_length_secret_key);
    

    return 0;
}

