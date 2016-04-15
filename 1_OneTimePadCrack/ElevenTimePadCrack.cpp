// Simple program to read a few ciphertexts encrypted using the one-time pad methodology (but used 11 times, so essentially an 11 time pad).
// This encryption is no longer perfectly secret, and the goal of this program is to decrypt ciphertext number 11.
// The methodology used is to use the fact that the one-time pad was applied by the XOR of the key and the plaintext using ascii format,
// such that space characters are easy to distinguish by examining the XOR of two different ciphertexts (provided the space coincides with some
// lower case text).
// Some manual adjustment is applied at the end to change the key to achieve the expected output (based on the mostly decrypted plaintext).

#include <vector>
#include <stdio.h>
#include <iostream>
#include <cstring> 
#include <string> 

using namespace std;

const int N_FILES = 11;
const int CHALLENGE_FILE = 11;

int main() {
  
  vector<vector<unsigned char> > ctexts; // Container for the 11 different cipher texts.
  vector<vector<int> > spaceLog;
  int i, j, k, tmp, maxLen = 0, longestCtext = 0;
  FILE *fpIn;
  
  spaceLog.resize(N_FILES);
    
  cout << "Ciphertexts:\n";
  
  // Read in all the 11 ciphertexts and store in ctexts vector container.
  // Log which file was longest and the length to use later.
  ctexts.resize(N_FILES);
  for(i=0; i<N_FILES; i++) {
    cout << i+1 << " - ";
    // Concatenate strings and read file
    char const* start = "11_TimePad_"; char const* ichar = to_string(i+1).c_str(); char const* end = ".txt";
    char str[20]; strcpy(str, start  ); strcat(str, ichar); strcat(str, end); 
    fpIn = fopen(str, "r");
    fseek(fpIn, 0, SEEK_END);   
    // Det file length.       
    long filelen = ftell(fpIn);    
    rewind(fpIn);
    int fileCount = 0;
    
    // Reading in hex format, so only read half length in.
    for(j=0; j<filelen/2; j++) {
      fscanf(fpIn, "%02x", &tmp);
      ctexts[i].push_back(tmp);
      cout << static_cast<int>(ctexts[i][fileCount]);  // print the ciphertext.
      fileCount++;
    }
    
    // Resize to the individual ciphertext length.
    spaceLog[i].resize(fileCount,0);
    
    if( fileCount > maxLen ) {
      maxLen = fileCount;
      longestCtext = i;
    }
    
    cout << endl;
    fclose(fpIn);
  }
  
  // Check XOR value of each text against each other to determine likely space positions.
  for(i=0; i<N_FILES-1; i++) {
    for(j=i+1; j<N_FILES; j++) {
      int minLen = ctexts[i].size() > ctexts[j].size() ? ctexts[j].size() : ctexts[i].size();
      for(k=0; k<minLen; k++) {
        //cout <<i<<" " << j << " " << k << endl;
        int xorTmp = ctexts[i][k] ^ ctexts[j][k];
        // Check whether this may be a space character in either underlying plaintext.
        // If so, increment possible space counter.
        if( xorTmp >= 65 ) {
          spaceLog[i][k] += 1;
          spaceLog[j][k] += 1;
        }
      }      
    }
  }
  
  // Given the 11 ciphertexts checked. Check which had the highest occurence of spaces at each
  // point and calculate the key value.
  vector<int> key;
  key.resize(maxLen,-999);
  
  cout << "\n\nGuessed key values: ";
  for(i=0; i<maxLen; i++) {
    int maxSpace = 0;
    int spaceFileIndex = longestCtext;  // default to longest ciphertext

    // Check for the most likely candidate that may contain a space among the ciphertexts.
    for(j=0; j<N_FILES; j++) {
      if(ctexts[j].size() > i) {
        if(spaceLog[j][i] > maxSpace) {
          maxSpace = spaceLog[j][i];
          spaceFileIndex = j;
        }
      }
    }
    
    // XOR space with ciphertext value in ciphertext with largest number of spaces (or equal largest).
    if(maxSpace > 0) {
      key[i] = 32 ^ ctexts[spaceFileIndex][i];
      cout << key[i] << " ";
    }
  }
  cout << endl;
  
  // Now output the estimate for the plaintext of ciphertext 11 (the challenge).
  cout << "\n\nFirst estimate of plaintext 11:" << endl;
  for(i=0; i<83; i++) {
    cout << static_cast<char>(key[i] ^ ctexts[CHALLENGE_FILE-1][i]);
  }
  
  // Some values were not estimated correctly (lack of spaces/other punctuation), but message is clear enough to make following adjustments.
  key[7] = key[7] ^ 'u' ^ 'r';
  key[25] = key[25] ^ 't' ^ 'e';
  key[26] = key[26] ^ '{' ^ 'n';
  key[35] = key[35] ^ 'a' ^ ' ';
  key[36] = key[36] ^ '~' ^ 's';
  key[39] = ctexts[CHALLENGE_FILE-1][39] ^ 'e';
  key[50] = key[50] ^ '.' ^ ' ';
  key[82] = key[82] ^ 't' ^ 'e';
  
  // Now output the estimate for the plaintext of ciphertext 11 (the challenge).
  cout << "\n\nFinal translation is:" << endl;
  for(i=0; i<83; i++) {
    cout << static_cast<char>(key[i] ^ ctexts[CHALLENGE_FILE-1][i]);
  }
  
  cout << "\n\n\nTry other ciphertexts out of curiosity (still mostly legible even though not all key values set):" << endl;
  for(i=0;i<N_FILES; i++) {
    cout << "Plaintext guess on ciphertext " << i+1 << endl;
    for(j=0; j<ctexts[i].size(); j++) {
      cout << static_cast<char>(key[j] ^ ctexts[i][j]);
    }
    cout << endl;
  }
  
  return 1;
}