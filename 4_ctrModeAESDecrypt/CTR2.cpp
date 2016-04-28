// Built using on Ubuntu:
// g++ -O0 -DNDEBUG -I/usr/include/cryptopp CTR2.cpp -o CTR2.out -lcryptopp
//

#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;

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
	byte iv[AES::BLOCKSIZE]          = {0x77, 0x0b, 0x80, 0x25, 0x9e, 0xc3, 0x3b, 0xeb, 0x25, 0x61, 0x35, 0x8a, 0x9f, 0x2d, 0xc6, 0x17};

	// String sink definitions.
	string cipher, encoded, recovered;
	// Provided ciphertext (hex encoded string).
	string cipherStringHex = "e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451";

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
