/*
 * s3fs - FUSE-based file system backed by Amazon S3
 *
 * Copyright 2007-2008 Randy Rizun <rrizun@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <iostream>
#include <sstream>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <unistd.h>
#include <iomanip>
#include <sys/stat.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>

// #include "s3fs.h"
// #include "common.h"
       
#define AES_BLOCK_SIZE 16

using namespace std;
  
namespace s3fs {
  
class Crypto
{
public:
    Crypto();
    ~Crypto();
    
    int preadAES(int fd, char *buf, size_t buflen, off_t offset);
    int pwriteAES(int fd, const char *buf, size_t buflen, off_t offset);
    int fstatAES(int fd, struct stat *st);
    void digest(string awsPrivateKey, string s, unsigned char *digest, unsigned int *dlen);
    string base64encode(unsigned char *s, unsigned int *len);

private:
    EVP_CIPHER_CTX ctx;
    unsigned char key[32];
    unsigned char iv[AES_BLOCK_SIZE];

    void gen_key();
    void gen_iv();
    int encrypt_block(const unsigned char plain[AES_BLOCK_SIZE], int inlen, unsigned char outbuf[AES_BLOCK_SIZE]);
    int decrypt_block(const unsigned char encrypted[AES_BLOCK_SIZE], int inlen, unsigned char outbuf[AES_BLOCK_SIZE]);
    void set_padding(unsigned char buffer[], int inlen);
    int get_padding(const unsigned char buffer[]);
};

}

#endif // CRYPTO_H
