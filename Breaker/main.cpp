#include "crypto/cryptoUtil.h"

#include <iostream>

using namespace std;


int main(void){

  const char* path = "/Users/anishnaik/Downloads/round1/sudo\ rm\ -rf/cmake-build-debug/nn_model";
  const char* evil = "/tmp/evilMLModel";
  const char* temp = "/tmp/scratchMlModel";
  CryptoUtil::secureDecryptFile(const_cast<char *>(evil), const_cast<char *>(path));
  FILE *srcFptr;
  FILE *dstFptr;
  srcFptr = fopen(evil, "rb");
  dstFptr = fopen(temp, "wb");
  fseek(srcFptr, 0, SEEK_END);    // seek to end of file
  int fsize = ftell(srcFptr);    // get current file pointer
  cout << fsize << endl;
  fseek(srcFptr, 0, SEEK_SET);    // seek back to beginning of file
  unsigned int allocSize = fsize;
  if (fsize % 16 != 0){
      allocSize = (fsize / 16 + 1) * 16;
  }
  char *content = (char *) malloc(allocSize);
  memset(content, 0, allocSize);
  // reads the file into memory
  fread(content, 1, fsize, srcFptr);
  content[0] = 'p';
  content[1] = 'o';
  content[2] = 'o';
  content[3] = 'l';
  fwrite(content, 1, allocSize, dstFptr);
  fclose(dstFptr);
  fclose(srcFptr);
  CryptoUtil::secureEncryptFile(const_cast<char *>(path), const_cast<char *>(temp));
  free(content);
  return 0;
}
