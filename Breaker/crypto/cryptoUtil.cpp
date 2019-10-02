#include "cryptoUtil.h"
#include "aes.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <iostream>
#include <termios.h>
#include <unistd.h>
#include <string>
using namespace std;

int CryptoUtil::getAesKey(unsigned char *keyBuffer, int keyLen) {
    int i;
    srand (time(NULL));

    for (i = 0; i< keyLen; i++){
        keyBuffer[i] = rand() % 256;
    }

    return 0;
}

int CryptoUtil::encryptKey(unsigned char *keyBuffer, int keyLen, const std::string& type) {
    int i;
    int n;
    string str;
    termios oldt;
    tcgetattr(STDIN_FILENO, &oldt);
    termios newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    cout << "Please enter passphrase to " << type << ":";
    getline (cin, str);

    printf("\n");

    n = str.length();

    if (n != 16) {
	while (n != 16) {
	    cout << "Passphrase must be 16 characters, try again:";
	    getline (cin, str);

	    printf("\n");

	    n = str.length();
	}
    }

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);

    char passPhrase[n + 1];

    strncpy(passPhrase, str.c_str(),16);

    for (i = 0; i< keyLen; i++){
	     keyBuffer[i] ^= passPhrase[i];
    }

    return 0;
}

int CryptoUtil::secureEncryptFile(char *dst, char *src) {
    // allocate the buffer for key
    unsigned char aesKey[16];

    // generate a fresh secret key to prevent brute force attack
    getAesKey(aesKey, 16);
    unsigned char iv[16];
    memset(iv, 0, 16);

    // open the file ptr
    FILE *dstFptr;
    FILE *srcFptr;
    srcFptr = fopen(src, "rb");
    dstFptr = fopen(dst, "wb");

    if(srcFptr==NULL || dstFptr==NULL)
    {
        printf("cannot open file src %s dst %s \n", src, dst );
        exit(-1);
    }

    // gets the file size
    fseek(srcFptr, 0, SEEK_END);    // seek to end of file
    int fsize = ftell(srcFptr);    // get current file pointer
    fseek(srcFptr, 0, SEEK_SET);    // seek back to beginning of file

    // allocate some memory to write the file content
    unsigned int allocSize = fsize;
    if (fsize % 16 != 0)
        allocSize = (fsize / 16 + 1) * 16;
    char *srcContent = (char *) malloc(allocSize);
    char *dstContent = (char *) malloc(allocSize);

    // zeroize memory
    memset(srcContent, 0, allocSize);

    // reads the file into memory
    fread(srcContent, 1, fsize, srcFptr);

    // memcpy(dstContent,srcContent,fsize);
    // encrypt the file content
    AES128_CBC_encrypt_buffer((uint8_t *) dstContent,
                              (uint8_t *) srcContent,
                              allocSize,
                              (uint8_t *) aesKey,
                              (uint8_t *) iv);

    // TODO assertion error here while encrypting mnist dataset "data/mnist/t10k-images.idx3-ubyte".
    // embeddedlab: malloc.c:2401: sysmalloc: Assertion `(old_top == initial_top (av) && old_size == 0) || ((unsigned long) (old_size) >= MINSIZE && prev_inuse (old_top) && ((unsigned long) old_end & (pagesize - 1)) == 0)' failed.
    // Process finished with exit code 134 (interrupted by signal 6: SIGABRT)
    // writes the key into the encrypted file
    encryptKey(aesKey, 16, "encrypt");

    fwrite(aesKey, 1, 16, dstFptr);

    // writes the length of the file into buffer
    fwrite(&fsize, 1, 4, dstFptr);

    // writes the encrypted content
    fwrite(dstContent, 1, allocSize, dstFptr);

    // we are done, close the file ptr
    fclose(srcFptr);
    fclose(dstFptr);

    // frees the allocated memory
    free(srcContent);
    free(dstContent);
    return 0;
}

int CryptoUtil::secureDecryptFile(char *dst, char *src) {
    // allocate the buffer for key
    unsigned char aesKey[16];
    unsigned char iv[16];
    memset(iv, 0, 16);
    // open the file ptr
    FILE *dstFptr;
    FILE *srcFptr;
    srcFptr = fopen(src, "rb");
    dstFptr = fopen(dst, "wb");

    if(srcFptr==NULL || dstFptr==NULL)
    {
        printf("cannot open file src %s dst %s \n", src, dst );
        exit(-1);
    }

    // gets the file size
    fseek(srcFptr, 0, SEEK_END);        // seek to end of file
    int fsize = ftell(srcFptr);         // get current file pointer
    fseek(srcFptr, 0, SEEK_SET);        // seek back to beginning of file
    unsigned int decryptedFileSize;    // file size of the expected decrypted file

    // allocate some memory to write the file content
    // we allocate an extra 16 bytes for the AES CBC padding
    char *srcContent = (char *) malloc(fsize + 16);
    char *dstContent = (char *) malloc(fsize + 16);

    // reads the file into memory
    fread(srcContent, 1, fsize, srcFptr);

    // recovers the AES encryption key
    memcpy(aesKey, srcContent, 16);

    encryptKey(aesKey, 16, "decrypt");

    // recovers the decrypted file size
    memcpy(&decryptedFileSize, srcContent + 16, 4);

    // recalculate the new offsets
    int decryptedBufferSize = fsize - 16 - 4;
    char *decryptedFileBuffer = dstContent;
    char *encryptedFileContent = srcContent + 16 + 4;

    // memcpy(dstContent,encryptedFileContent,decryptedFileSize);
    //encrypt the file content
    AES128_CBC_decrypt_buffer((uint8_t *) decryptedFileBuffer,
                              (uint8_t *) encryptedFileContent,
                              decryptedBufferSize,
                              (uint8_t *) aesKey,
                              (uint8_t *) iv);

    // writes the encrypted content
    fwrite(dstContent, 1, decryptedFileSize, dstFptr);

    // we are done, close the file ptr
    fclose(srcFptr);
    fclose(dstFptr);

    // frees the allocated memory
    free(srcContent);
    free(dstContent);

    return 0;
}
