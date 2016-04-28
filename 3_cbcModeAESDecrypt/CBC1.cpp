// Built using on Ubuntu:
// g++ -O0 -I/usr/include/cryptopp CBC1.cpp -o CBC1.out -lcryptopp
//
// The goal of this code is to decrypt a message that was encrypted using AES-128 in
// CBC mode. The key and ciphertext (including IV) are provided.
//
// Only two ciphertexts were to be decrypted, so read in of a file for decryption was not implemented. Note,
// CryptoPP does provide simple file read functions.


#include <iostream>

// Cryptopp Includes
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>


using namespace std;

int main(int argc, char* argv[])
{

  // Provided key and IV.
  byte key[16] = {0x14, 0x0b, 0x41, 0xb2, 0x2a, 0x29, 0xbe, 0xb4, 0x06, 0x1b, 0xda, 0x66, 0xb6, 0x74, 0x7e, 0x14};
  byte iv[16]  = {0x5b, 0x68, 0x62, 0x9f, 0xeb, 0x86, 0x06, 0xf9, 0xa6, 0x66, 0x76, 0x70, 0xb7, 0x5b, 0x38, 0xa5};
  // Provided ciphertext.
  byte cbCipherText[48] = {0xb4, 0x83, 0x2d, 0x0f, 0x26, 0xe1, 0xab, 0x7d, 0xa3, 0x32, 0x49, 0xde, 0x7d, 0x4a, 0xfc, 0x48, 0xe7, 0x13, 0xac, 0x64, 0x6a, 0xce, 0x36, 0xe8, 0x72, 0xad, 0x5f, 0xb8, 0xa5, 0x12, 0x42, 0x8a, 0x6e, 0x21, 0x36, 0x4b, 0x0c, 0x37, 0x4d, 0xf4, 0x55, 0x03, 0x47, 0x3c, 0x52, 0x42, 0xa2, 0x53};

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
