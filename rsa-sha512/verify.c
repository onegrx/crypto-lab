#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/md5.h>
#include <openssl/sha.h>


unsigned char* md5sum(char* inputFileName){
  FILE* inputFile;
  unsigned char inputVector[16];
  unsigned char* md5Vector= (unsigned char*)malloc(16*sizeof(unsigned char));
  if ( (inputFile=fopen(inputFileName, "rb"))==NULL ) {
    fprintf(stderr, "Otwarcie pliku %s nie powiodlo sie\n", inputFileName);
    exit(1);
  }

  MD5_CTX hashChunk;
  MD5_Init(&hashChunk);

  size_t bytesRead;
  while( bytesRead=fread(inputVector, sizeof(char), sizeof(inputVector), inputFile) ) {
    MD5_Update(&hashChunk, inputVector, bytesRead);
  }
  MD5_Final(md5Vector, &hashChunk);

  return md5Vector;
}

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
	if ( argc!=4 ) {
	    fprintf(stderr, "Poprawna skladnia:\n verify nazwaPlikuKlucza nazwaPlikuDoWeryfikacji plikPodpisu\n");
	    return 1;
	}

	char* keyFileName = argv[1];
	char* toVerifyFileName = argv[2];
	char* signFileName = argv[3];

	FILE* keyFile;
	FILE* signFile;
	RSA* rsaPublicKey;

	unsigned char* md5Vector;
	unsigned int signLength;

	long keySize;
	unsigned char* buffer;
	unsigned char* buffer2;

	rsaPublicKey=RSA_new();
	if ( (keyFile=fopen(keyFileName,"rb")) == NULL ) {
		fprintf(stderr, "Nie moge otworzyc pliku klucza publicznego\n");
		return 1;
	}

	if( (signFile=fopen(signFileName,"rb")) == NULL ) {
		fprintf(stderr, "Nie moge otworzyc pliku z podpisem\n");
		fclose(keyFile);
		return 1;
	}

	fseek(keyFile,0,SEEK_END);
	keySize=ftell(keyFile);
	rewind(keyFile);

	buffer=(unsigned char*)malloc(keySize*sizeof(unsigned char));
	buffer2=buffer;
	fread(buffer,sizeof(unsigned char),keySize,keyFile);

	d2i_RSAPublicKey(&rsaPublicKey,(const unsigned char**)&buffer2,keySize);

	fclose(keyFile);
	free(buffer);

	if ( rsaPublicKey==NULL ) {
		fprintf(stderr, "Nie moge wczytac klucza publicznego\n");
		return 1;
	}

	md5Vector=sha512sum(toVerifyFileName);

	fseek(signFile,0,SEEK_END);
	signLength=ftell(signFile);
	rewind(signFile);

	buffer=(unsigned char*)malloc(signLength*sizeof(unsigned char));
	fread(buffer,sizeof(unsigned char),signLength,signFile);
	fclose(signFile);

	if( (RSA_verify(NID_sha512,md5Vector,sizeof(md5Vector),buffer,signLength,rsaPublicKey)) == 1 ) {
		printf("Podpis jest autentyczny\n");
	} else {
		printf("Podpis jest sfalszowany\n");
	}

	free(md5Vector);
	free(buffer);
	RSA_free(rsaPublicKey);

	return 0;

}
