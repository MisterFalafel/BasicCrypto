// Compiled using:
// g++ -O0 -DNDEBUG -I/usr/include/cryptopp computeSHAMAC.cpp -o SHAMAC.out -lcryptopp

// The goal of this program is to compute the hash on a video file.
// The methodology for hashing has been defined so that a partially downloaded file
// may still be verified. This is done as follows:
// 1. Compute hash of final block (may be less than block size if file is not integer multiple of block).
// 2. Append the computed hash to the next block and compute the hash.
// 3. Repeat step 2 for all blocks, the final value after computing the hash of the first block (with
//    hash appended) is the hash for the file.
// A user downloading the video will recieve each block + appended hash, and may compute the resulting
// hash and compare with hash for the previous block (or the actual file hash if it is the first block).
// This program simply computes the overall hash value for a file, following this methodology.

#include <string>
#include <vector>
#include <fstream>
#include <iostream>

// CryptoPP includes.
#include <cryptopp/files.h>
#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>

using namespace std;

// File to hash and block size in bytes.
const char FILE_TO_HASH[] = "download1.mp4";
const int BLOCK_SIZE = 1024;

int main() {

  int i;
  // Read in all bytes of file to hash.
  string fileBytes;
  CryptoPP::FileSource in(FILE_TO_HASH, true, new CryptoPP::StringSink(fileBytes));
  cout << "File to be hashed: " << FILE_TO_HASH << endl;
  // String sinks.
  string prevHashval;
  // SHA256 hash object.
  CryptoPP::SHA256 hash;

  // Get number of whole blocks in file (integer divide).
  int nWholeBlocks = fileBytes.length() / BLOCK_SIZE;
  cout << "Number of whole blocks: " << nWholeBlocks << endl;

  // hash the last black if a partial block.
  if( fileBytes.length() > nWholeBlocks*BLOCK_SIZE) {
    int lastBlockSize = fileBytes.length() - nWholeBlocks*BLOCK_SIZE;
    CryptoPP::StringSource ss( fileBytes.substr(nWholeBlocks*BLOCK_SIZE, lastBlockSize),
                   true /* PumpAll */,
                   new CryptoPP::HashFilter( hash,
                       new CryptoPP::StringSink( prevHashval )
                   ) // HashFilter
                ); // StringSource
  }

  // Go through all remaining whole blocks and compute hash on the block + previous hash.
  for(i=(nWholeBlocks-1)*BLOCK_SIZE; i>=0; i -= BLOCK_SIZE) {
    string tempHashVal;
    //cout << "Block " << i << endl;
    //cout << "hash " << value << endl;
    CryptoPP::StringSource ss( fileBytes.substr(i, BLOCK_SIZE) + prevHashval, true /* PumpAll */,
                   new CryptoPP::HashFilter( hash,
                       new CryptoPP::StringSink( tempHashVal )
                   ) // HashFilter
                ); // StringSource
    prevHashval = tempHashVal;

  }

  string outValue;
  CryptoPP::StringSource(prevHashval, true,
      new CryptoPP::HexEncoder(
          new CryptoPP::StringSink(outValue)
      ) // HexEncoder
  ); // StringSource

  cout << "Hash value computed for file:" << endl;
  cout << outValue << endl;
  return 0;
}
