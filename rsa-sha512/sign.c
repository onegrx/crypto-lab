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

  if (argc !=3 ) {
		printf("Usage: ./sign [file_to_sign] [private_key]\n");
		return 1;
	}

  char* filenameToSign = argv[1];
	char* filenameKey = argv[2];
	char* signatureFilename;

	FILE* keyFile;
	FILE* signFile;

	long keySize;
	RSA* rsaPrivateKey;

	unsigned char* hashVector;

	unsigned char* buffer;
	unsigned char* buffer2;

	signatureFilename = (char*) malloc(130);
	strcpy(signatureFilename, filenameToSign);
	const char *ext = ".sig";
	strcat(signatureFilename, ext);

	rsaPrivateKey = RSA_new();
	if ((keyFile = fopen(filenameKey, "rb")) == NULL ) {
		printf("Cannot open private key\n");
		return 1;
	}

	fseek(keyFile, 0, SEEK_END);
	keySize = ftell(keyFile);
	rewind(keyFile);

	buffer = (unsigned char*) malloc(keySize*sizeof(unsigned char));
	buffer2 = buffer;
	fread(buffer, sizeof(unsigned char), keySize, keyFile);

	d2i_RSAPrivateKey(&rsaPrivateKey, (const unsigned char**) &buffer2, keySize);

	fclose(keyFile);
	free(buffer);

	if(rsaPrivateKey == NULL) {
		printf("Cannot read private key\n");
		return 1;
	}

  hashVector = sha512sum(filenameToSign);

  //buffer to keep signature
	buffer = (unsigned char*) malloc(RSA_size(rsaPrivateKey));
	unsigned int signLength;
	if((RSA_sign(NID_sha512, hashVector, sizeof(hashVector), buffer, &signLength, rsaPrivateKey)) == 0) {
		printf("Error while trying to sign the file\n");
		return 1;
	}

	if((signFile = fopen(signatureFilename, "wb")) == NULL) {
		printf("Cannot open/create file to keep signature\n");
		return 1;
	}
	fwrite(buffer, sizeof(unsigned char), signLength, signFile);

	fflush(signFile);
	fclose(signFile);

	free(buffer);
	free(hashVector);
	free(signatureFilename);
	RSA_free(rsaPrivateKey);

	return 0;

}
