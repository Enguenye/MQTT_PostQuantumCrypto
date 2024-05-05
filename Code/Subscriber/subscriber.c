#include <stdio.h>
#include <string.h>
#include <MQTTClient.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <oqs/oqs.h>
#include <stdint.h>

#define MESSAGE_LEN 100

#define ADDRESS     "tcp://localhost:1883" 
#define CLIENTID    "ExampleClientSub"
#define TOPIC       "MQTT/KEY"
#define TOPIC2       "MQTT/DATA"
#define QOS         1
#define FIXED_SIZE 1024

uint8_t shared_secret_d[OQS_KEM_frodokem_640_aes_length_shared_secret]; // AES key size

void print_hex(const unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// Function to convert hexadecimal string to binary data
void fromHex(const char *hexStr, uint8_t *data, size_t length) {
    for (size_t i = 0; i < length; i++) {
        sscanf(hexStr + 2 * i, "%2hhx", &data[i]);
    }
}

int importKeyFromFile(const char *filename, uint8_t *key, size_t key_length) {
    FILE *file = fopen(filename, "r");
    if (!file) return -1;

    char hexKey[key_length * 2 + 1];
    fgets(hexKey, sizeof(hexKey), file);

    fromHex(hexKey, key, key_length);
    fclose(file);
    return 0;
}

// Function to decode Base64 to binary
unsigned char *base64Decode(const char *input, int *length) {
    BIO *b64, *bmem;
    int inputLength = strlen(input);
    unsigned char *buffer = (unsigned char *)malloc(inputLength);

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new_mem_buf(input, inputLength);
    bmem = BIO_push(b64, bmem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // No newlines

    *length = BIO_read(b64, buffer, inputLength);
    BIO_free_all(b64);

    return buffer;
}

#include <openssl/bio.h>
#include <openssl/evp.h>

int base64DecodeFixedSize(const char *input, unsigned char *output, int outputSize) {
    BIO *b64, *bmem;
    int inputLength = strlen(input);
    int decodedLength;

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new_mem_buf(input, inputLength);
    bmem = BIO_push(b64, bmem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // No newlines

    decodedLength = BIO_read(b64, output, outputSize);
    BIO_free_all(b64);

    return decodedLength; // Return the number of bytes read
}


void onMessageDelivered(void *context, MQTTClient_deliveryToken dt) {
    printf("Message with token %d delivery confirmed\n", dt);
}

void initializeFixedSizeArray(const char *input, char output[FIXED_SIZE]) {
    strncpy(output, input, FIXED_SIZE - 1);  // Copy up to FIXED_SIZE-1 chars
    output[FIXED_SIZE - 1] = '\0';  // Ensure null-termination
}

int onMessageArrived(void *context, char *topicName, int topicLen, MQTTClient_message *message) {
    printf("Message arrived on topic: %s\n", topicName);
    
    
    OQS_STATUS rc2;
    int decodedLength;
    const int chunk_size = 190; // Maximum size for RSA encryption with padding
    int num_chunks = 52;
    
    if (strcmp(topicName, TOPIC) == 0) {
        unsigned char *encrypted_aes_key = base64Decode((char *)message->payload, &decodedLength);
   

    // Load the RSA private key from a file
    FILE *privateKeyFile = fopen("privateRSA_key.pem", "rb");
    RSA *rsa = PEM_read_RSAPrivateKey(privateKeyFile, NULL, NULL, NULL);
    fclose(privateKeyFile);

    if (!rsa) {
        perror("Failed to read private key");
        free(encrypted_aes_key);
        return 1;
    }
    
    uint8_t secret_keyk[OQS_KEM_frodokem_640_aes_length_secret_key];
    importKeyFromFile("secret_key.txt", secret_keyk, OQS_KEM_frodokem_640_aes_length_secret_key);

    unsigned char frodo_cipher[OQS_KEM_frodokem_640_aes_length_ciphertext]; // Ensure this is large enough to hold the reassembled key
	int decrypted_position = 0; // Keeps track of where to copy the decrypted data

	for (int i = 0; i < num_chunks; i++) {
	    unsigned char decrypted_buffer[chunk_size + 1]; // Temporary buffer for decryption, +1 for safety
	    int offset = i * RSA_size(rsa); // Calculate offset for this chunk in the encrypted data

	    // Decrypt this chunk
	    int result = RSA_private_decrypt(RSA_size(rsa), encrypted_aes_key + offset, decrypted_buffer, rsa, RSA_PKCS1_OAEP_PADDING);
	    if (result == -1) {
		// Handle decryption error
		ERR_print_errors_fp(stderr);
		exit(1); // Or appropriate error handling
	    }

	    // Copy decrypted chunk into position
	    memcpy(frodo_cipher + decrypted_position, decrypted_buffer, result);
	    decrypted_position += result;
	}

    
    //Cristals kyber decryption
    
    
    rc2 = OQS_KEM_frodokem_640_aes_decaps(shared_secret_d, frodo_cipher, secret_keyk);
	if (rc2 != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_KEM_frodokem_640_aes_decaps failed!\n");
		//cleanup_stack(secret_key, OQS_KEM_frodokem_640_aes_length_secret_key,           shared_secret_e, shared_secret_d,OQS_KEM_frodokem_640_aes_length_shared_secret);

		return OQS_ERROR;
	}

    } else if (strcmp(topicName, TOPIC2) == 0) {
        // Decrypt the message with AES-256-CBC using the decrypted AES key

    int decodedLength2;
	
	
	char *encoded_message = strtok(message->payload, "...");
	char *encoded_signature = strtok(NULL, "...");
	
	uint8_t *encrypted_message = base64Decode(encoded_message, &decodedLength2);

	size_t signature_len;
	char *signature = base64Decode(encoded_signature, &signature_len);
    unsigned char iv[16]="47ab92cf290834aa"; // 128 bit, adjust size according to the cipher mode
    
    uint8_t public_key[OQS_SIG_dilithium_2_length_public_key];
    importKeyFromFile("publicDith_key.txt", public_key, OQS_SIG_dilithium_2_length_public_key);


	
    rc2 = OQS_SIG_dilithium_2_verify(encoded_message, strlen(encoded_message), signature, 2420, public_key);
	if (rc2 != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_SIG_dilithium_2_verify failed!\n");
		//cleanup_stack(secret_key, OQS_SIG_dilithium_2_length_secret_key);
		return OQS_ERROR;
	}
	else{
	   fprintf(stderr,"Verified signature over Crystals kyber key\n");
	}

    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(ctx, 1); 
    int len2;
    unsigned char decrypted_message[1024]; // Ensure the buffer is large enough
    if ( EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, shared_secret_d, iv)!= 1) {
    ERR_print_errors_fp(stderr);
}
   if ( EVP_DecryptUpdate(ctx, decrypted_message, &len2, encrypted_message, decodedLength2)!= 1) {
    ERR_print_errors_fp(stderr);
}
int decrypted_message_len = len2;
if ( EVP_DecryptFinal_ex(ctx, decrypted_message + len2, &len2)!= 1) {
    ERR_print_errors_fp(stderr);
}
      
    decrypted_message_len += len2;
   

    decrypted_message[decrypted_message_len] = '\0'; // Null-terminate the decrypted message
    printf("Decrypted Message: %s\n", decrypted_message);
    } else {
        printf("Unknown topic\n");
    }
    
    



    return 1;
}



void onConnectionLost(void *context, char *cause) {
    printf("Connection lost, cause: %s\n", cause);
}

int main(int argc, char* argv[]) {
    MQTTClient client;
    MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;
    int rc;

    MQTTClient_create(&client, ADDRESS, CLIENTID, MQTTCLIENT_PERSISTENCE_NONE, NULL);
    conn_opts.keepAliveInterval = 20;
    conn_opts.cleansession = 1;

    MQTTClient_setCallbacks(client, NULL, onConnectionLost, onMessageArrived, onMessageDelivered);

    if ((rc = MQTTClient_connect(client, &conn_opts)) != MQTTCLIENT_SUCCESS) {
        printf("Failed to connect, return code %d\n", rc);
        return -1;
    }

    printf("Subscribing to topic %s with QoS %d\n", TOPIC, QOS);
    MQTTClient_subscribe(client, TOPIC, QOS);
    
    printf("Subscribing to topic %s with QoS %d\n", TOPIC2, QOS);
    MQTTClient_subscribe(client, TOPIC2, QOS);

    // Keep the client running to listen to incoming messages
    while(1) {
        sleep(1);
    }

    MQTTClient_disconnect(client, 10000);
    MQTTClient_destroy(&client);
    return rc;
}
