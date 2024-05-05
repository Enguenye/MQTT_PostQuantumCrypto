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

void exportRSAKeys(RSA *rsa, const char *privateKeyFile, const char *publicKeyFile) {
    // Export Private Key
    FILE *privateFile = fopen(privateKeyFile, "wb");
    if (!privateFile) {
        perror("Unable to open file for writing private key");
        return;
    }
    PEM_write_RSAPrivateKey(privateFile, rsa, NULL, NULL, 0, NULL, NULL);
    fclose(privateFile);

    // Export Public Key
    FILE *publicFile = fopen(publicKeyFile, "wb");
    if (!publicFile) {
        perror("Unable to open file for writing public key");
        return;
    }
    PEM_write_RSA_PUBKEY(publicFile, rsa);
    fclose(publicFile);
}

int main() {
    uint8_t public_keyk[OQS_KEM_frodokem_640_aes_length_public_key];
    uint8_t secret_keyk[OQS_KEM_frodokem_640_aes_length_secret_key];

    int rc2 = OQS_KEM_frodokem_640_aes_keypair(public_keyk, secret_keyk);
    if (rc2 != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_KEM_frodokem_640_aes_keypair failed!\n");
        return -1;
    }

    exportKeyToFile("public_key.txt", public_keyk, OQS_KEM_frodokem_640_aes_length_public_key);
    exportKeyToFile("secret_key.txt", secret_keyk, OQS_KEM_frodokem_640_aes_length_secret_key);
    
    // Generate RSA Key Pair
    RSA *rsa = RSA_new();
    BIGNUM *bne = BN_new();
    if (BN_set_word(bne, RSA_F4) != 1 || RSA_generate_key_ex(rsa, 2048, bne, NULL) != 1) {
        fprintf(stderr, "RSA key generation failed\n");
        return 1;
    }
    BN_free(bne);
    
    // Export the keys to text files
    exportRSAKeys(rsa, "privateRSA_key.pem", "publicRSA_key.pem");

    // Free RSA structure
    RSA_free(rsa);

    return 0;
}

