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
#define CLIENTID    "ExampleClientPub"
#define TOPIC       "MQTT/KEY"
#define TOPIC2       "MQTT/DATA"
#define PAYLOAD     "Hello MQTT"
#define QOS         1
#define TIMEOUT     10000L

void print_hex(const unsigned char *data, size_t length) {
    for (size_t i = 0; i < length; i++) {
        printf("%02X", data[i]);
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

// Function to encode binary data to Base64
char *base64Encode(const unsigned char *input, int length) {
    BIO *b64, *bmem;
    BUF_MEM *bptr;

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // No newlines
    BIO_write(b64, input, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);

    char *buff = (char *)malloc(bptr->length + 1);
    memcpy(buff, bptr->data, bptr->length);
    buff[bptr->length] = '\0';

    BIO_free_all(b64);

    return buff;
}

int main(int argc, char* argv[]) {
	if (argc < 2) {
    fprintf(stderr, "Usage: %s <message>\n", argv[0]);
    return 1;
}
    MQTTClient client;
    MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;
    int rc;
    OQS_STATUS rc2;

    MQTTClient_create(&client, ADDRESS, CLIENTID, MQTTCLIENT_PERSISTENCE_NONE, NULL);
    conn_opts.keepAliveInterval = 20;
    conn_opts.cleansession = 1;

    if ((rc = MQTTClient_connect(client, &conn_opts)) != MQTTCLIENT_SUCCESS) {
        printf("Failed to connect, return code %d\n", rc);
        return -1;
    }
    



    //Crystals kyber AES Key
    uint8_t public_keyk[OQS_KEM_frodokem_640_aes_length_public_key];

    importKeyFromFile("public_key.txt", public_keyk, OQS_KEM_frodokem_640_aes_length_public_key);
    
    uint8_t ciphertext[OQS_KEM_frodokem_640_aes_length_ciphertext];
    uint8_t shared_secret_e[OQS_KEM_frodokem_640_aes_length_shared_secret];
    rc2 = OQS_KEM_frodokem_640_aes_encaps(ciphertext, shared_secret_e, public_keyk);
	if (rc2 != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_KEM_frodokem_640_aes_encaps failed!\n");
		//cleanup_stack(secret_key, OQS_KEM_frodokem_640_aes_length_secret_key,shared_secret_e, shared_secret_d,OQS_KEM_frodokem_640_aes_length_shared_secret);

		return OQS_ERROR;
	}
	
	FILE *file = fopen("publicRSA_key.pem", "rb");
    	if (!file) {
        	perror("Unable to open public key file");
        	return NULL;
    	}
    	RSA *rsa = PEM_read_RSA_PUBKEY(file, NULL, NULL, NULL);
    	fclose(file);
	
	// RSA Encrypt AES Key
	const int chunk_size = 190; // Maximum size for RSA encryption with padding
	int num_chunks = (sizeof(ciphertext) + chunk_size - 1) / chunk_size; // Calculate number of chunks, rounding up
	int total_length = 0; // Initialize total length

	unsigned char encrypted_aes_key[RSA_size(rsa) * num_chunks]; // Array to hold all encrypted chunks

	for (int i = 0; i < num_chunks; i++) {
	    int offset = i * chunk_size;
	    int size = ((i + 1) * chunk_size > sizeof(ciphertext)) ? (sizeof(ciphertext) - i * chunk_size) : chunk_size;
	    unsigned char buffer[RSA_size(rsa)]; // Temporary buffer for this chunk's encryption

	    int result = RSA_public_encrypt(size, ciphertext + offset, buffer, rsa, RSA_PKCS1_OAEP_PADDING);
	    if (result == -1) {
		// Handle encryption error
		break;
	    }
	    
	    // Copy the encrypted chunk into the correct position in encrypted_aes_key
	    memcpy(encrypted_aes_key + i * RSA_size(rsa), buffer, result);
	    total_length += result;
	}
	
    
    // Encode the encrypted message to Base64
    char *encodedMessage = base64Encode(encrypted_aes_key, sizeof(encrypted_aes_key));
    
    
    MQTTClient_message pubmsg = MQTTClient_message_initializer;
    pubmsg.payload = encodedMessage;
    pubmsg.payloadlen = strlen(encodedMessage);
    pubmsg.qos = QOS;
    pubmsg.retained = 0;

    MQTTClient_deliveryToken token;
    MQTTClient_publishMessage(client, TOPIC, &pubmsg, &token);
    printf("Waiting for publication of %s on topic %s for client with ClientID: %s\n",
           PAYLOAD, TOPIC, CLIENTID);
    rc = MQTTClient_waitForCompletion(client, token, TIMEOUT);
    printf("Message with delivery token %d delivered\n", token);
    
        // Encrypt the message with AES-256-CBC
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char encrypted_message[1024]; // Ensure the buffer is large enough for encryption + padding
    int len;
    int encrypted_message_len = 0;
    
    // Generate IV
    unsigned char iv[16]="47ab92cf290834aa";  // 128 bit, adjust size according to the cipher mode

    // Message to be encrypted
    unsigned char *message = (unsigned char *)argv[1];
    EVP_CIPHER_CTX_set_padding(ctx, 1); 
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, shared_secret_e, iv);
    EVP_EncryptUpdate(ctx, encrypted_message, &len, message, strlen((char *)message));
    encrypted_message_len += len;
    EVP_EncryptFinal_ex(ctx, encrypted_message + len, &len);
    encrypted_message_len += len;
    
    
    char *encodedMessage2 = base64Encode(encrypted_message, encrypted_message_len);
    
        //Crystals dithilium Signing key
    uint8_t secret_key[OQS_SIG_dilithium_2_length_secret_key];

    importKeyFromFile("secretDith_key.txt", secret_key, OQS_SIG_dilithium_2_length_secret_key);
    
    
    // Sign the keys with Dilithium
    uint8_t signature[OQS_SIG_dilithium_2_length_signature];
    size_t signature_len;
    
    rc2 = OQS_SIG_dilithium_2_sign(signature, &signature_len, encodedMessage2, strlen(encodedMessage2), secret_key);
	if (rc2 != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_SIG_dilithium_2_sign failed!\n");
		//cleanup_stack(secret_key, OQS_SIG_dilithium_2_length_secret_key);
		return OQS_ERROR;
	}


	
	
	char *encoded_signature = base64Encode(signature, signature_len);
	
	size_t concatenated_length = strlen(encodedMessage2) + strlen(encoded_signature) + 4; // Include space for delimiter
	char *concatenated_data = malloc(concatenated_length);
	snprintf(concatenated_data, concatenated_length, "%s...%s", encodedMessage2, encoded_signature);

    
    MQTTClient_message pubmsg2 = MQTTClient_message_initializer;
    pubmsg2.payload = concatenated_data;
    pubmsg2.payloadlen = strlen(concatenated_data);
    pubmsg2.qos = QOS;
    pubmsg2.retained = 0;
    
   
    
    MQTTClient_publishMessage(client, TOPIC2, &pubmsg2, &token);
    printf("Waiting for publication of %s on topic %s for client with ClientID: %s\n",
           PAYLOAD, TOPIC2, CLIENTID);
           
    rc = MQTTClient_waitForCompletion(client, token, TIMEOUT);
    printf("Message with delivery token %d delivered\n", token);

    MQTTClient_disconnect(client, 10000);
    MQTTClient_destroy(&client);
    return rc;
}
