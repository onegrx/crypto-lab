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
		fprintf(stderr, "Poprawna skladnia:\n sign nazwaPlikuDoPodpisania nazwaPlikuKluczaPrywatnego\n");
		return 1;
	}

	char* keyFileName = argv[2];
	char* toSignFileName = argv[1];
	char* signFileName;

	FILE* keyFile;
	FILE* signFile;

	long keySize;
	RSA* rsaPrivateKey;

	unsigned char* md5Vector;

	unsigned char* buffer;
	unsigned char* buffer2;

	signFileName=(char*)malloc(130);
	strcpy(signFileName,toSignFileName);
	const char *ext = ".sig";
	strcat(signFileName, ext);

	rsaPrivateKey=RSA_new();
	if ( (keyFile=fopen(keyFileName, "rb")) == NULL ) {
		fprintf(stderr, "Nie moge otworzyc pliku do odczytu klucza prywatnego\n");
		return 1;
	}

	fseek(keyFile, 0, SEEK_END);
	keySize=ftell(keyFile);
	rewind(keyFile);

	buffer=(unsigned char*)malloc(keySize*sizeof(unsigned char));
	buffer2=buffer;
	fread(buffer, sizeof(unsigned char), keySize, keyFile);

	d2i_RSAPrivateKey(&rsaPrivateKey,(const unsigned char**)&buffer2,keySize);

	fclose(keyFile);
	free(buffer);

	if( rsaPrivateKey == NULL ) {
		fprintf(stderr, "Nie moge wczytac klucza prywatnego\n");
		return 1;
	}

	// md5Vector=md5sum(toSignFileName);
  md5Vector = sha512sum(toSignFileName);

	buffer=(unsigned char*)malloc(RSA_size(rsaPrivateKey));//miejsce na podpis
	unsigned int signLength;
	if( (RSA_sign(NID_sha512,md5Vector,sizeof(md5Vector),buffer,&signLength,rsaPrivateKey)) == 0 ) {
		fprintf(stderr, "Nie udalo sie podpisac pliku\n");
		return 1;
	}

	if( (signFile=fopen(signFileName,"wb")) == NULL ) {
		fprintf(stderr, "Nie udalo sie otworzyc pliku do zapisu podpisu\n");
		return 1;
	}
	fwrite(buffer, sizeof(unsigned char), signLength, signFile);

	fflush(signFile);
	fclose(signFile);

	free(buffer);
	free(md5Vector);
	free(signFileName);
	RSA_free(rsaPrivateKey);

	return 0;

}
