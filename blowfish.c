#include <openssl/blowfish.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char usage[] = "./blowfish <input> <output> <secret_key> -cbc/ecb -encrypt/decrypt";
int cbc_mode, encrypt;

FILE *input, *output;

char ini_vector[8];
unsigned char buffer[8];
unsigned char out_buffer[8];
int byte_read;

int first_loop = 1;

BF_KEY bfkey;

int parse_input(int argc, char* argv[]) {
  if (!strcmp(argv[4],"-cbc")) {
    cbc_mode = 1;
  } else if (!strcmp(argv[4],"-ecb")) {
    cbc_mode = 0;
  } else {
    puts(usage);
    return 1;
  }

  if (!strcmp(argv[5], "-encrypt")) {
    encrypt = BF_ENCRYPT;
  } else if (!strcmp(argv[5], "-decrypt")) {
    encrypt = BF_DECRYPT;
  } else {
    puts(usage);
    return 1;
  }

  return 0;
}

char encrypt_or_decrypt() {
  char padding_value;
  while ((byte_read = fread(buffer, 1, 8, input))) {

    //If not first pass, write buffer to output
    if((encrypt == BF_DECRYPT) && !first_loop) {
      fwrite(out_buffer, 1, 8, output);
    }

    if((byte_read) < 8 && (encrypt == BF_ENCRYPT)) {
      padding_value = 8 - byte_read;
      int padding_index = padding_value - 1;
      while(padding_index >= 0) {
        buffer[7 - padding_index] = padding_value;
        padding_index--;
      }
    }
    else {
      padding_value = 0;
    }

    first_loop = 0;

    if (cbc_mode == 1) {
      BF_cbc_encrypt(buffer, out_buffer, 8, &bfkey, ini_vector, encrypt);
    } else {
      BF_ecb_encrypt(buffer, out_buffer, &bfkey, encrypt);
    }

    if (encrypt == BF_ENCRYPT) {
      fwrite(out_buffer, 1, 8, output);
    }
  }
  return padding_value;
}

int main(int argc, char* argv[]) {

  if (argc < 6) {
    printf("%s\n", usage);
    return 1;
  }

  if (parse_input(argc, argv)) exit(1);

  //Set Blowfish key
  char *key = argv[3];
  BF_set_key(&bfkey, strlen(key), key);

  //Open files
  input = fopen(argv[1], "rb");
  output = fopen(argv[2], "wb");
  if((input == 0) || (output == 0)) {
    printf("%s\n", usage);
    return 1;
  }

  memset(ini_vector, 0, 8);

  char padding_value = encrypt_or_decrypt();

	if (encrypt == BF_DECRYPT) {
		int out_count = 8 - out_buffer[7];
		fwrite(out_buffer, 1, out_count, output);
	}

	if ((encrypt == BF_ENCRYPT) && (padding_value == 0)) {
		memset(buffer, 8, 8);

		if (cbc_mode == 1) {
			BF_cbc_encrypt(buffer, out_buffer, 8, &bfkey, ini_vector, encrypt);
		} else {
			BF_ecb_encrypt(buffer, out_buffer, &bfkey, encrypt);
		}

		fwrite(out_buffer, 1, 8, output);

	}
	fclose(input);
	fclose(output);
	return 0;
}
