#include <stdlib.h>
#include <stdio.h>
#include <openssl/rsa.h>

int main(int argc, char* argv[]) {

	if (argc < 2) {
		printf("Usage: ./keygen [private_key] [public_key]\n");
		return 1;
	}

	char* privateKeyFile = argv[1];
	char* publicKeyFile = argv[2];
	FILE* output;

	int keyLength = 1024;
	int exp = 3;
	int pkcsLength;
	unsigned char* buffer1;
	unsigned char* buffer2;

	RSA* rsaKey = RSA_generate_key(keyLength, exp, NULL, NULL);

	if (RSA_check_key(rsaKey) != 1) {
		printf("Invalid key");
		return 1;
	}

  //Generate public key
	if ((output = fopen(publicKeyFile, "wb")) == NULL) {
		printf("Cant't open public key file\n");
		return 1;
	}

	pkcsLength = i2d_RSAPublicKey(rsaKey, NULL);
	buffer1 = (unsigned char*) malloc(pkcsLength * sizeof(unsigned char));
	buffer2 = buffer1;
	i2d_RSAPublicKey(rsaKey, &buffer2);

	fwrite(buffer1, sizeof(unsigned char), pkcsLength, output);
	fflush(output);
	fclose(output);
	free(buffer1);

  //Generate private key
	if ((output = fopen(privateKeyFile, "wb")) == NULL) {
    printf("Cant't open private key file\n");
		return 1;
	}

	pkcsLength = i2d_RSAPrivateKey(rsaKey, NULL);
	buffer1 = (unsigned char*) malloc(pkcsLength * sizeof(unsigned char));
	buffer2 = buffer1;
	i2d_RSAPrivateKey(rsaKey, &buffer2);

	fwrite(buffer1, sizeof(unsigned char), pkcsLength, output);
	fflush(output);
	fclose(output);
	free(buffer1);

	RSA_free(rsaKey);
  return 0;
}
