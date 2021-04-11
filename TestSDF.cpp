#include "SDFCryptoProvider.h"
#include<string>
#include<iostream>

using namespace std;
using namespace dev;
using namespace crypto;

int main(int, const char* argv[]){
    // SDFCryptoProvider& provider = SDFCryptoProvider::GetInstance();
    // char * input = (char *)malloc(8*sizeof(char));
    // strncpy(input,"test-sdf",8);

    // // Make hash
    // cout << "**************Make SM3 Hash************************"<<endl;
    // unsigned char bHashData[64] = {0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,
    //                             0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,
    //                             0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,
    //                             0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64};

    // unsigned char bHashStdResult[32] = {0xde,0xbe,0x9f,0xf9,0x22,0x75,0xb8,0xa1,0x38,0x60,0x48,0x89,0xc1,0x8e,0x5a,0x4d,
    //                                 0x6f,0xdb,0x70,0xe5,0x38,0x7e,0x57,0x65,0x29,0x3d,0xcb,0xa3,0x9c,0x0c,0x57,0x32};
    // unsigned char bHashResult[32];
    // unsigned int uiHashResultLen;
    // unsigned int code = provider.Hash(nullptr,SM3,(char *)bHashData,64, bHashResult, &uiHashResultLen);
    // cout << "****Make Hash****" << endl;
    // cout<<"Call Hash:" << provider.GetErrorMessage(code) << endl;
    // PrintData((char *)"Cal Hash",bHashResult,32,16);
    // PrintData((char *)"Std Hash",bHashStdResult,32,16);
    // if((uiHashResultLen != 32) || (memcmp(bHashStdResult, bHashResult, 32) != 0))
    // {
	// cout << "result is not match"<<endl;
    // }else{
    // 	cout << "result is match" <<endl;
    // }

    // Key key=Key();
    // code = provider.KeyGen(SM2,&key);
    // cout << "****KeyGen****" << endl;
    // cout << provider.GetErrorMessage(code) << endl;
    // PrintData((char *)"public key",key.PublicKey(),64,16);
    // PrintData((char *)"private Key",key.PrivateKey(),32,16);

    // cout << "****Sign****" << endl;
    // unsigned char * signature = (unsigned char *)malloc(64*sizeof(char));
    // unsigned int len;
    // provider.Sign(key,SM2,(char *)bHashResult,32,signature,&len);
    // cout << provider.GetErrorMessage(code) << endl;
    // PrintData((char *)"signature",signature,len,16);

    // cout << "****Verify****" << endl;
    // bool result;
    // code = provider.Verify(key,SM2,(char *)bHashResult,32,(char *)signature,64,&result);
    // cout << provider.GetErrorMessage(code) << endl;
    // cout <<"verify result: "<< result <<endl;

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
        SignWithInternalKey(1, "123456", SM2, toHex(bHashStdResult, 32));
    cout << "****SignInternalKey****" << endl;
    if (signResult.sdfErrorMessage != nullptr){
        cout << "Get error : " << signResult.sdfErrorMessage <<endl;
    }else{
        cout << "Get signature: " << signResult.signature << endl;
    }

    cout << "****VerifyInternalKey****" << endl;
    verifyResult = VerifyWithInternalKey(1, SM2, toHex(bHashStdResult, 32),
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

