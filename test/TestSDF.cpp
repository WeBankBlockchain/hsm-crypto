#include <sdf/SDFCryptoProvider.h>
#include<string>
#include<iostream>

using namespace std;
using namespace dev;
using namespace crypto;

int main(int, const char* argv[]){
    // Make hash
    cout << "**************Make SM3 Hash************************"<<endl;
    unsigned char bHashData[64] = {0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,
                                0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,
                                0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,
                                0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64};

    unsigned char bHashStdResult[32] = {0xde,0xbe,0x9f,0xf9,0x22,0x75,0xb8,0xa1,0x38,0x60,0x48,0x89,0xc1,0x8e,0x5a,0x4d,
                                    0x6f,0xdb,0x70,0xe5,0x38,0x7e,0x57,0x65,0x29,0x3d,0xcb,0xa3,0x9c,0x0c,0x57,0x32};
    SDFCryptoResult result = Hash(nullptr,SM3,toHex(bHashData,64));
    if (result.sdfErrorMessage != nullptr){
        cout << "Get error : " << result.sdfErrorMessage <<endl;
    }else{
        cout << "Get Hash : " << result.hash << endl;
        cout << "Standard : " << toHex(bHashStdResult,32) <<endl;
    }
    
    result = KeyGen(SM2);
    cout << "****KeyGen****" << endl;
    if (result.sdfErrorMessage != nullptr){
        cout << "Get error : " << result.sdfErrorMessage <<endl;
    }else{
        cout << "Get public key : " << result.publicKey << endl;
        cout << "Get private key : " << result.privateKey << endl;
    }

    SDFCryptoResult signResult = Sign(result.privateKey,SM2,toHex(bHashStdResult,32));
    cout << "****Sign****" << endl;
    if (signResult.sdfErrorMessage != nullptr){
        cout << "Get error : " << signResult.sdfErrorMessage <<endl;
    }else{
        cout << "Get signature: " << signResult.signature << endl;
    }

    cout << "****Verify****" << endl;
    SDFCryptoResult verifyResult = Verify(result.publicKey,SM2,toHex(bHashStdResult,32),signResult.signature);
    if (verifyResult.sdfErrorMessage != nullptr){
        cout << "Get error : " << verifyResult.sdfErrorMessage <<endl;
    }else{
        cout << "Get verify result: " << verifyResult.result << endl;
    }

    signResult =
        SignWithInternalKey(1, "123456", SM2,(const char*) toHex(bHashStdResult, 32));
    cout << "****SignInternalKey****" << endl;
    if (signResult.sdfErrorMessage != nullptr){
        cout << "Get error : " << signResult.sdfErrorMessage <<endl;
    }else{
        cout << "Get signature: " << signResult.signature << endl;
    }

    cout << "****VerifyInternalKey****" << endl;
    verifyResult = VerifyWithInternalKey(1, SM2, (const char *)toHex(bHashStdResult, 32),
                                         signResult.signature);
    if (verifyResult.sdfErrorMessage != nullptr){
        cout << "Get error : " << verifyResult.sdfErrorMessage <<endl;
    }else{
        cout << "Get verify result: " << verifyResult.result << endl;
    }

    cout << "*****ExportInternalPublicKey****" << endl;
    SDFCryptoResult exportResult = ExportInternalPublicKey(2, SM2);
    cout << "Export public key: " << exportResult.publicKey << endl;
    return 0;
}

