#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/sha.h>

unsigned char* sha512sum(char* inputFile) {
  unsigned char *buff;
  int count;
  FILE* file = fopen(inputFile, "rb");
  if (!file) {
    printf("Could not open signed file\n");
    exit(1);
  }

  SHA512_CTX ctx;
  SHA512_Init(&ctx);
  buff = (unsigned char *) malloc(256);

  do {
    count = fread(buff, 1, 256, file);
    if (count) {
      SHA512_Update(&ctx, (unsigned char *)buff, count);
    }
  } while (count == 256);
  fclose(file);

  SHA512_Final(buff, &ctx);
  return buff;
}

int main(int argc, char* argv[]) {
	if (argc != 4) {
	    printf("Usage: ./verify [public_key] [file_to_verify] [signature_file]\n");
	    return 1;
	}

	char* filenameKey = argv[1];
	char* filenameToVerify = argv[2];
	char* filenameSignature = argv[3];

	FILE* keyFile;
	FILE* signFile;
	RSA* rsaPublicKey;

	unsigned char* hashVector;
	unsigned int signLength;

	long keySize;
	unsigned char* buffer;
	unsigned char* buffer2;

	rsaPublicKey = RSA_new();

	if((keyFile = fopen(filenameKey, "rb")) == NULL) {
		printf("Cannot open file with public key\n");
		return 1;
	}

	if((signFile = fopen(filenameSignature, "rb")) == NULL) {
		printf("Cannot open file with signature\n");
		fclose(keyFile);
		return 1;
	}

	fseek(keyFile, 0, SEEK_END);
	keySize = ftell(keyFile);
	rewind(keyFile);

	buffer = (unsigned char*) malloc(keySize * sizeof(unsigned char));
	buffer2 = buffer;
	fread(buffer, sizeof(unsigned char), keySize, keyFile);

	d2i_RSAPublicKey(&rsaPublicKey, (const unsigned char**) &buffer2, keySize);

	fclose(keyFile);
	free(buffer);

	if (rsaPublicKey == NULL) {
		printf("Cannot read public key\n");
		return 1;
	}

	hashVector = sha512sum(filenameToVerify);

	fseek(signFile, 0, SEEK_END);
	signLength = ftell(signFile);
	rewind(signFile);

	buffer = (unsigned char*) malloc(signLength * sizeof(unsigned char));
	fread(buffer, sizeof(unsigned char), signLength, signFile);
	fclose(signFile);

	if((RSA_verify(NID_sha512, hashVector, sizeof(hashVector), buffer, signLength, rsaPublicKey)) == 1) {
		printf("The file is genuine\n");
	} else {
		printf("The file is NOT original - it has been changed\n");
	}

	free(hashVector);
	free(buffer);
	RSA_free(rsaPublicKey);

	return 0;

}
