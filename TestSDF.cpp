#include "SDFCryptoProvider.h"
#include<string>
#include<iostream>

using namespace std;
using namespace dev;
using namespace crypto;

int main(int, const char* argv[]){
    SDFCryptoProvider& provider = SDFCryptoProvider::GetInstance();
    char * input = (char *)malloc(8*sizeof(char));
    strncpy(input,"test-sdf",8);
    char * out = new char[64];
    unsigned int outLen;
    unsigned int code = provider.Hash(nullptr,dev::crypto::SM3 , (const char*)input, 8, out,&outLen);
    cout << provider.GetErrorMessage(code) << endl;
    cout << out <<endl;
    return 0;
}
