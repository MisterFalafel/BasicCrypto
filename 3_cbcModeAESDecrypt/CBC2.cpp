// Built using on Ubuntu:
// g++ -O0 -I/usr/include/cryptopp CBC2.cpp -o CBC2.out -lcryptopp
//
// See CBC1.cpp comments. This is simply decrypting another ciphertext.
// Only two ciphertexts were to be decrypted, so read in of a file for decryption was not implemented. Note,
// CryptoPP does provide simple file read functions.

#include "stdafx.h"

// Runtime Includes
#include <iostream>
#include <iomanip>

// Cryptopp Includes
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>    // StringSource and
                        // StreamTransformation

int main(int argc, char* argv[])
{

  // Provided key and IV.
  byte key[16] = {0x14, 0x0b, 0x41, 0xb2, 0x2a, 0x29, 0xbe, 0xb4, 0x06, 0x1b, 0xda, 0x66, 0xb6, 0x74, 0x7e, 0x14};
  byte iv[16]  = {0x4c, 0xa0, 0x0f, 0xf4, 0xc8, 0x98, 0xd6, 0x1e, 0x1e, 0xdb, 0xf1, 0x80, 0x06, 0x18, 0xfb, 0x28};
  byte cbCipherText[48] = {0x28, 0xa2, 0x26, 0xd1, 0x60, 0xda, 0xd0, 0x78, 0x83, 0xd0, 0x4e, 0x00, 0x8a, 0x78, 0x97, 0xee, 0x2e, 0x4b, 0x74, 0x65, 0xd5, 0x29, 0x0d, 0x0c, 0x0e, 0x6c, 0x68, 0x22, 0x23, 0x6e, 0x1d, 0xaa, 0xfb, 0x94, 0xff, 0xe0, 0xc5, 0xda, 0x05, 0xd9, 0x47, 0x6b, 0xe0, 0x28, 0xad, 0x7c, 0x1d, 0x81};

  // Sink for recovered text.
  std::string decryptedtext;

  // Length of ciphertext.
  int cipherLen = sizeof(cbCipherText) / sizeof(byte);
  cout << "Ciphertext length (bytes):" << endl;
  cout << cipherLen << endl;

  // Define aes and cbc decryption objects using key and IV.
  CryptoPP::AES::Decryption aesDecryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
  CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption( aesDecryption, iv );

  // Define stream transform filter object to decrypt into string sink.
  CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption,
    new CryptoPP::StringSink( decryptedtext )
  );

  // Decrypt the ciphertext.
  stfDecryptor.Put( reinterpret_cast<const unsigned char*>( cbCipherText ), cipherLen );
  stfDecryptor.MessageEnd();

  cout << "Decrypted Text: " << endl;
  cout << decryptedtext << endl;

  return 0;
}
