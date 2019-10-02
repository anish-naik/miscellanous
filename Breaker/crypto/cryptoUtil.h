#ifndef CRYPTO_UTIL_H
#define CRYPTO_UTIL_H

#include <ctime>
#include <cstring>
#include <string>

class CryptoUtil {
public:
    static int getAesKey(unsigned char *keyBuffer, int keyLen);

    static int encryptKey(unsigned char *keyBuffer, int keyLen, const std::string&);

    static int secureEncryptFile(char *dst, char *src);

    static int secureDecryptFile(char *dst, char *src);
};

#endif 
