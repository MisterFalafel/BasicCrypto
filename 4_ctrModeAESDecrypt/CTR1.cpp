// Built using on Ubuntu:
// g++ -O0 -DNDEBUG -I/usr/include/cryptopp CTR1.cpp -o CTR1.out -lcryptopp
//
// The goal of this program is to decrypt a ciphertext encrypted using AES-128 in CTR mode, with
// the ciphertext, key and IV are provided.

#include <iostream>
using std::cout;
using std::endl;

#include <string>
using std::string;

#include <cstdlib>
using std::exit;

#include <cryptopp/hex.h>
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include <cryptopp/filters.h>
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

#include <cryptopp/aes.h>
using CryptoPP::AES;

#include <cryptopp/ccm.h>
using CryptoPP::CTR_Mode;

int main(int argc, char* argv[])
{
	// Provided key and IV definition.
	byte key[AES::DEFAULT_KEYLENGTH] = {0x36, 0xf1, 0x83, 0x57, 0xbe, 0x4d, 0xbd, 0x77, 0xf0, 0x50, 0x51, 0x5c, 0x73, 0xfc, 0xf9, 0xf2};
	byte iv[AES::BLOCKSIZE]          = {0x69, 0xdd, 0xa8, 0x45, 0x5c, 0x7d, 0xd4, 0x25, 0x4b, 0xf3, 0x53, 0xb7, 0x73, 0x30, 0x4e, 0xec};

	// String sink definitions.
	string cipher, encoded, recovered;
	// Provided ciphertext (hex encoded string).
	string cipherStringHex = "0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329";

	// Put key into string to print.
	encoded.clear();
	StringSource(key, sizeof(key), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	cout << "Key: " << encoded << endl;

	// Put IV into string to print.
	encoded.clear();
	StringSource(iv, sizeof(iv), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	cout << "IV: " << encoded << endl;

	CTR_Mode< AES >::Encryption e;
	e.SetKeyWithIV(key, sizeof(key), iv);

	// Decode hex ciphertext and put in cipher sink.
	StringSource(cipherStringHex, true,
		new HexDecoder(
			new StringSink(cipher)
		) // HexDecoder
	); // StringSource

	// Print out ciphertext (hex).
	cout << "Cipher text: " << cipherStringHex << endl;

	CTR_Mode< AES >::Decryption decryptor;
	decryptor.SetKeyWithIV(key, sizeof(key), iv);

	// The StreamTransformationFilter removes
	//  padding as required.
	StringSource ss(cipher, true,
		new StreamTransformationFilter(decryptor,
			new StringSink(recovered)
		) // StreamTransformationFilter
	); // StringSource

	cout << "Recovered text: " << recovered << endl;

	return 0;
}
