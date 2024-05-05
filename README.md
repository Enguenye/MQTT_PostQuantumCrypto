# MQTT_PostQuantumCrypto
MQTT protected with Post Quantum cryptography on C

# Instructions:

## Compilation.
To compile the binary, the following libraries must be installed:

- OpenSSL: https://github.com/openssl/openssl
- Liboqs: https://github.com/open-quantum-safe/liboqs
- Paho MQTT C Client Library: https://eclipse.github.io/paho.mqtt.c/MQTTClient/html/

## Running the binaries.
A broker must be installed and both the client and subscriber files should be pointed to the broker. The binaries are the following:

- The subscriberKeyGen file generates both the Public and Private RSA keys and the Public and Private Crystals-Kybers keys. The public keys must be put on the Publisher's folder.
- The publisherKeyGen file generates the Public and Private Crystals-Dithilium keys. The public key must be put on the Subscriber's folder.
- The subscriber file starts listening on the MQTT/Key and MQTT/Data topics on the broker.
- The publisher file with an argument sends the argument as a message to the subscriber(after doing the AES key exchange and signing the message).

