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

#include "crypto.h"

s3fs::Crypto::Crypto()
{
//     FGPRINT("s3fs::Crypto Initializing a crypto object\n");
//     SYSLOGERR("s3fs::Crypto Initializing a crypto object");
    gen_key();
    gen_iv();
}

s3fs::Crypto::~Crypto()
{
//     FGPRINT("s3fs::Crypto deleting the instance of the crypto object\n");
//     SYSLOGERR("s3fs::Crypto deleting the instance of the crypto object");
}

// *******************************************
// Public Function Implementation
// *******************************************
int s3fs::Crypto::preadAES(int fd, char *buf, size_t buflen, off_t offset)
{
    unsigned char readBlock[AES_BLOCK_SIZE];
    unsigned char writeBlock[AES_BLOCK_SIZE];
    unsigned char buffer[sizeof(char[buflen])];
    size_t offsetIndex = offset % AES_BLOCK_SIZE;
    size_t readOffset = offset - offsetIndex;
    int bytesRead = 0;
    int byteIndex = 0;
    int padlen = 0;
    int filesize = 0;
    struct stat st;
    
    if(fstat(fd, &st) != 0)
      return 1;

    filesize = st.st_size;
    
//     FGPRINT("s3fs::Crypto Encrypted filesize %ld\n", filesize);
//     SYSLOGERR("s3fs::Crypto Encrypted filesize %ld", filesize);
    
    //Read the last cipher block to determine the true file size
    memset(readBlock, 0, AES_BLOCK_SIZE);
    memset(writeBlock, 0, AES_BLOCK_SIZE);
    bytesRead = pread(fd, readBlock, AES_BLOCK_SIZE, (filesize - AES_BLOCK_SIZE));
    if(bytesRead > 0)
    {
	memset(writeBlock, 0, AES_BLOCK_SIZE);
	decrypt_block(readBlock, bytesRead, writeBlock);
	padlen = get_padding(writeBlock);
// 	FGPRINT("s3fs::Crypto Encrypted padding length %d\n", padlen);
	filesize -= padlen;
    }
        
    if(buflen > filesize)
      buflen = filesize;
    
    memset(readBlock, 0, AES_BLOCK_SIZE);
    memset(writeBlock, 0, AES_BLOCK_SIZE);
    memset(buffer, 0, sizeof(buffer));
    do {
        memset(readBlock, 0, AES_BLOCK_SIZE);
        bytesRead = pread(fd, readBlock, AES_BLOCK_SIZE, readOffset);
        if(bytesRead > 0)
        {
            memset(writeBlock, 0, AES_BLOCK_SIZE);
            decrypt_block(readBlock, bytesRead, writeBlock);
            readOffset += bytesRead;
            if(byteIndex == 0 )
            {
                memcpy((buffer + byteIndex), (writeBlock + offsetIndex), (bytesRead - offsetIndex));
                byteIndex += (bytesRead - offsetIndex);
            }
            else if((byteIndex + bytesRead) <= buflen)
            {
                memcpy((buffer + byteIndex), writeBlock, bytesRead);
                byteIndex += bytesRead;
            }
            else
            {
                memcpy((buffer + byteIndex), writeBlock, (bytesRead - ((byteIndex + bytesRead) - buflen)));
                byteIndex += ((byteIndex + bytesRead) - buflen);
            }
        }
        else
        {
            break;
        }
    } while(byteIndex <= buflen);

    if(byteIndex < buflen)
    {
        memcpy(buf, buffer, byteIndex);
        return byteIndex;
    }

    memcpy(buf, buffer, buflen);
    return buflen;
}

int s3fs::Crypto::pwriteAES(int fd, const char *buf, size_t buflen, off_t offset)
{
    char readBlock[AES_BLOCK_SIZE];
    unsigned char writeBlock[AES_BLOCK_SIZE];
    unsigned char buffer[AES_BLOCK_SIZE];
    size_t offsetIndex = offset % AES_BLOCK_SIZE;
    size_t readOffset = offset - offsetIndex;
    size_t writeOffset = readOffset;
    size_t bufIndex = 0;
    bool newfile = false;
    int bytesRead = 0;
    int bytesWritten = 0;
    int enclen = 0;
    struct stat st;

    memset(readBlock, 0, AES_BLOCK_SIZE);
    memset(writeBlock, 0, AES_BLOCK_SIZE);
    memset(buffer, 0, AES_BLOCK_SIZE);

    do {
        if(!newfile)
        {
	    if(fstatAES(fd, &st) != 0)
	      return 1;
	  
            bytesRead = preadAES(fd, readBlock, AES_BLOCK_SIZE, readOffset);
            if(bytesRead <= 0)
            {
                newfile = true;
                continue;
            }

            memcpy(buffer, readBlock, bytesRead); //Fill the buffer with contents from the readBlock
            if(bufIndex <= 0)
            {
                memcpy((buffer + offsetIndex), (buf + bufIndex), (AES_BLOCK_SIZE - offsetIndex));
                enclen += (bytesRead + ((buflen - bufIndex) >= AES_BLOCK_SIZE) ? AES_BLOCK_SIZE : (buflen - bufIndex));
		bufIndex += (AES_BLOCK_SIZE - offsetIndex);
            }
            else
            {
                memcpy(buffer, (buf + bufIndex), ((buflen - bufIndex) >= AES_BLOCK_SIZE) ? AES_BLOCK_SIZE : (buflen - bufIndex));
		enclen += ((buflen - bufIndex) >= AES_BLOCK_SIZE) ? AES_BLOCK_SIZE : (buflen - bufIndex);
                bufIndex += ((buflen - bufIndex) >= AES_BLOCK_SIZE) ? AES_BLOCK_SIZE : (buflen - bufIndex);
            }

            //Set padding if needed
            if(enclen < AES_BLOCK_SIZE && ((st.st_size - buflen) < AES_BLOCK_SIZE))
	    {
	      set_padding(buffer, enclen);
	      int padlen = get_padding(buffer);
// 	      FGPRINT("s3fs::Crypto Encrypted padding length %d\n", padlen);
	    }
	    else if (enclen == AES_BLOCK_SIZE && bufIndex == buflen)
	    { 
	      encrypt_block(buffer, AES_BLOCK_SIZE, writeBlock);
	      bytesWritten = pwrite(fd, &writeBlock, AES_BLOCK_SIZE, writeOffset);
	      
	      memset(buffer, 0, AES_BLOCK_SIZE);
	      set_padding(buffer, 0);
	      int padlen = get_padding(buffer);
// 	      FGPRINT("s3fs::Crypto Encrypted padding length %d\n", padlen);
	    }
       
            encrypt_block(buffer, AES_BLOCK_SIZE, writeBlock);
            bytesWritten = pwrite(fd, &writeBlock, AES_BLOCK_SIZE, writeOffset);
            writeOffset += bytesWritten;
            readOffset += bytesRead;
        }
        else
        {
            memset(buffer, 0, AES_BLOCK_SIZE);
            memcpy(buffer, (buf + bufIndex), ((buflen - bufIndex) >= AES_BLOCK_SIZE) ? AES_BLOCK_SIZE : (buflen - bufIndex));
	    enclen += ((buflen - bufIndex) >= AES_BLOCK_SIZE) ? AES_BLOCK_SIZE : (buflen - bufIndex);
	    bufIndex += ((buflen - bufIndex) >= AES_BLOCK_SIZE) ? AES_BLOCK_SIZE : (buflen - bufIndex);

            if(enclen < AES_BLOCK_SIZE)
	    {
	      set_padding(buffer, enclen);
	      int padlen = get_padding(buffer);
// 	      FGPRINT("s3fs::Crypto Encrypted padding length %d\n", padlen);
	    }
	    else if (enclen == AES_BLOCK_SIZE && bufIndex == buflen)
	    { 
	      encrypt_block(buffer, AES_BLOCK_SIZE, writeBlock);
	      bytesWritten = pwrite(fd, &writeBlock, AES_BLOCK_SIZE, writeOffset);
	      writeOffset += bytesWritten;
	      
	      memset(buffer, 0, AES_BLOCK_SIZE);
	      set_padding(buffer, 0);
	      int padlen = get_padding(buffer);
// 	      FGPRINT("s3fs::Crypto Encrypted padding length %d\n", padlen);
	    }

	    encrypt_block(buffer, AES_BLOCK_SIZE, writeBlock);
	    bytesWritten = pwrite(fd, &writeBlock, AES_BLOCK_SIZE, writeOffset);
	    writeOffset += bytesWritten;
        }

        memset(readBlock, 0, AES_BLOCK_SIZE);
        memset(writeBlock, 0, AES_BLOCK_SIZE);
        memset(buffer, 0, AES_BLOCK_SIZE);
	enclen = 0;

    } while(bufIndex < buflen);

    return bufIndex;
}

int s3fs::Crypto::fstatAES(int fd, struct stat *st)
{
  char buf[AES_BLOCK_SIZE];
  
  memset(buf, 0, AES_BLOCK_SIZE);
  if(fstat(fd, st) == 0)
  {
    int bytesRead = preadAES(fd, buf, AES_BLOCK_SIZE, (st->st_size - AES_BLOCK_SIZE));
    int padlen = get_padding((unsigned char*)buf);
    st->st_size -= padlen;

    return 0;
  }
  
  return 1;
}

void s3fs::Crypto::digest(std::string awsPrivateKey, std::string s, unsigned char *digest, unsigned int *dlen)
{  
  HMAC_CTX ctx;
  HMAC_CTX_init(&ctx);
  HMAC_Init_ex(&ctx, awsPrivateKey.c_str(), awsPrivateKey.length(), EVP_sha1(), NULL);
  HMAC_Update(&ctx, (unsigned char*)s.c_str(), s.length());
  HMAC_Final(&ctx, digest, dlen);
  HMAC_CTX_cleanup(&ctx);
}

std::string s3fs::Crypto::base64encode(unsigned char *s, unsigned int *slen)
{
  ostringstream signature;
  
  BIO *b64 = BIO_new(BIO_f_base64());
  BIO *bio = BIO_new(BIO_s_mem());
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  b64 = BIO_push(b64, bio);
  int bytesWritten = BIO_write(b64, s, *slen);
  if(bytesWritten <= 0)
    cerr << "A problem occurred writing out base64" << endl;
  
  int res = BIO_flush(b64);
  if(res <= 0)
    cerr << "A problem occurred flushing BIO" << endl;
  
  BUF_MEM *bptr;
  BIO_get_mem_ptr(b64, &bptr);
  signature << bptr->data;

  BIO_free_all(b64);

  return signature.str();
}


// *******************************************
// Private Function Implementation
// *******************************************
void s3fs::Crypto::gen_key()
{
    //Get a random key for encryption and decryption for this instance
    FILE *urand = fopen("/dev/urandom", "rb");
    if (urand == NULL) {
        cerr << "Could not open /dev/urandom to read random key data" << endl;
    }
    if (fread(key, 1, 32, urand) != 32) {
        cerr << "Could not read all 256 bits of random key" << endl;
        abort();
    }
    fclose(urand);
}

void s3fs::Crypto::gen_iv()
{
    //Get a random key for encryption and decryption for this instance
    FILE *urand = fopen("/dev/urandom", "rb");
    if (urand == NULL) {
        cerr << "Could not open /dev/urandom to read random key data" << endl;
    }
    if (fread(iv, 1, 16, urand) != 16) {
        cerr << "Could not read all 128 bits of random key" << endl;
        abort();
    }
    fclose(urand);
}

int s3fs::Crypto::encrypt_block(const unsigned char plain[], int inlen, unsigned char outbuf[])
{
    int outlen;
    int tmplen;

    EVP_CIPHER_CTX_init(&ctx);
    EVP_CIPHER_CTX_set_padding(&ctx, 1L);
    EVP_EncryptInit_ex(&ctx, EVP_aes_256_ctr() , NULL, key, iv);    
    if(!EVP_EncryptUpdate(&ctx, outbuf, &outlen, plain, inlen))
    {
        cerr << "An error has occurred while encrypting the plain text." << endl;
        EVP_CIPHER_CTX_cleanup(&ctx);
    }
    if(!EVP_EncryptFinal_ex(&ctx, outbuf + outlen, &tmplen))
    {
        cerr << "An error has occurred while encrypting the plain text." << endl;
        EVP_CIPHER_CTX_cleanup(&ctx);
    }
    outlen += tmplen;
    EVP_CIPHER_CTX_cleanup(&ctx);

    return outlen;
}

int s3fs::Crypto::decrypt_block(const unsigned char encrypted[], int inlen, unsigned char outbuf[])
{
    int outlen;
    int tmplen;

    EVP_CIPHER_CTX_init(&ctx);
    EVP_CIPHER_CTX_set_padding(&ctx, 1L);
    EVP_DecryptInit_ex(&ctx, EVP_aes_256_ctr(), NULL, key, iv);
    if(!EVP_DecryptUpdate(&ctx, outbuf, &outlen, encrypted, inlen))
    {
        cerr << "An error has occurred while decrypting the encrypted text." << endl;
        EVP_CIPHER_CTX_cleanup(&ctx);
    }
    if(!EVP_DecryptFinal_ex(&ctx, outbuf + outlen, &tmplen))
    {
        cerr << "An error has occurred while decrypting the encrypted text." << endl;
        EVP_CIPHER_CTX_cleanup(&ctx);
    }
    outlen += tmplen;
    EVP_CIPHER_CTX_cleanup(&ctx);

    return outlen;
}

void s3fs::Crypto::set_padding(unsigned char buffer[], int inlen)
{
    ostringstream os;
    
    int padlen = ((AES_BLOCK_SIZE - inlen) - 1);
    os << hex << padlen;
    
    for(int i = inlen; i < AES_BLOCK_SIZE; i++)
      buffer[i] = (unsigned char)os.str().c_str()[0];
}

int s3fs::Crypto::get_padding(const unsigned char buffer[])
{
    stringstream ss;
    int padlen = 0;

    ss << buffer[15];
    ss >> hex >> padlen;

    return padlen + 1;
}
