#include "gmt0018.h"
#include <hsm/sdf/SDFCryptoProvider.h>
#include <exception>
#include <iostream>
#include <string>
#include <thread>

using namespace std;
using namespace hsm;
using namespace hsm::sdf;


void callCard(int inum)
{
    for( int i = 0; i < inum; i++){
        SDFCryptoProvider& provider = SDFCryptoProvider::GetInstance();
        Key key = Key();
        unsigned int code = provider.KeyGen(SM2, &key);
        if (code != SDR_OK)
        {
            cout << provider.GetErrorMessage(code) << endl;
        }
    }
}

int hextostr(const unsigned char* hex, unsigned int hlen, unsigned char* str)
{
    unsigned int len = hlen;
    const unsigned char HexStr[]="0123456789ABCDEF";

    while(len--)
    {
        *str++ = HexStr[(*hex)>>4];
        *str++ = HexStr[(*hex)&0x0f];
        hex++;
    }

    return (hlen<<1);
}

int main(int, const char* argv[]){
    // Crypto provider 测试
    cout << "**************Begin Test, bash test-sdf-crypto [sessionPoolSize] "
            "[loopRound]************************"
         << endl;
    size_t sessionPoolRound = atoi(argv[1]);
    size_t loopRound = atoi(argv[2]);
    try
    {
        SDFCryptoProvider& provider = SDFCryptoProvider::GetInstance(sessionPoolRound);
    }
    catch (const std::exception& e)
    {
        cout << "error occured, info: " << e.what() << endl;
        exit(1);
    }
    SDFCryptoProvider& provider = SDFCryptoProvider::GetInstance(sessionPoolRound);

    // Make hash
    cout << "**************Make SM3 Hash************************"<<endl;
    std::vector<byte> bHashVector = {0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,
                                0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,
                                0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,
                                0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64};

    std::vector<byte> bHashStdResultVector = {0xde,0xbe,0x9f,0xf9,0x22,0x75,0xb8,0xa1,0x38,0x60,0x48,0x89,0xc1,0x8e,0x5a,0x4d,
                                    0x6f,0xdb,0x70,0xe5,0x38,0x7e,0x57,0x65,0x29,0x3d,0xcb,0xa3,0x9c,0x0c,0x57,0x32};
    SDFCryptoResult result = Hash(nullptr, SM3, sdfToHex(bHashVector));
    if (result.sdfErrorMessage != nullptr){
        cout << "Get error : " << result.sdfErrorMessage <<endl;
    }else{
        cout << "Get Hash : " << result.hash << endl;

        cout << "Standard : " << sdfToHex(bHashStdResultVector) << endl;
    }

    cout << "****KeyGen****" << endl;
    result = KeyGen(SM2);
    if (result.sdfErrorMessage != nullptr){
        cout << "Get error : " << result.sdfErrorMessage <<endl;
    }else{
        cout << "Get public key : " << result.publicKey << endl;
        cout << "Get private key : " << result.privateKey << endl;
    }
    
    cout << "**************Make SM2_SM3 Hash************************"<<endl;
    SDFCryptoResult sm2_sm3_result = Hash(result.publicKey, SM3, sdfToHex(bHashVector));
    if (sm2_sm3_result.sdfErrorMessage != nullptr)
    {
        cout << "Get error : " << sm2_sm3_result.sdfErrorMessage << endl;
    }
    else
    {
        cout << "SM2_SM3 : " << sm2_sm3_result.hash << endl;
    }

    cout << "****Sign****" << endl;
    SDFCryptoResult signResult;
    signResult = Sign(result.privateKey, SM2, sdfToHex(bHashStdResultVector));
    if (signResult.sdfErrorMessage != nullptr){
        cout << "Get error : " << signResult.sdfErrorMessage <<endl;
    }else{
        cout << "Get signature: " << signResult.signature << endl;
    }

    cout << "****Verify****" << endl;
    SDFCryptoResult verifyResult;
    verifyResult = Verify(
        result.publicKey, SM2, hsm::sdf::sdfToHex(bHashStdResultVector), signResult.signature);
    if (verifyResult.sdfErrorMessage != nullptr){
        cout << "Get error : " << verifyResult.sdfErrorMessage <<endl;
    }else{
        cout << "Get verify result: " << verifyResult.result << endl;
    }

    cout << "****SignInternalKey****" << endl;
    signResult = SignWithInternalKey(1, "12345678", SM2, sdfToHex(bHashStdResultVector));
    if (signResult.sdfErrorMessage != nullptr){
        cout << "Get error : " << signResult.sdfErrorMessage <<endl;
    }else{
        cout << "Get signature: " << signResult.signature << endl;
    }

    cout << "****VerifyInternalKey****" << endl;
    verifyResult = VerifyWithInternalKey(
        1, SM2, (const char*)sdfToHex(bHashStdResultVector), signResult.signature);
    if (verifyResult.sdfErrorMessage != nullptr){
        cout << "Get error : " << verifyResult.sdfErrorMessage <<endl;
    }else{
        cout << "Get verify result: " << verifyResult.result << endl;
    }

    cout << "*****ExportInternalPublicKey****" << endl;
    SDFCryptoResult exportResult = ExportInternalPublicKey(1, SM2);
    cout << "Export public key: " << exportResult.publicKey << endl;


    cout << "*****SM4 Encrypt****" << endl;
    const std::vector<byte> pkv = {0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    std::shared_ptr<const std::vector<byte>> pbKeyValue =
        std::make_shared<const std::vector<byte>>(pkv);
    std::vector<byte> originIV = {0xeb, 0xee, 0xc5, 0x68, 0x58, 0xe6, 0x04, 0xd8, 0x32, 0x7b, 0x9b,
        0x3c, 0x10, 0xc9, 0x0c, 0xa7};
    std::vector<byte> pbIV = {0xeb,0xee,0xc5,0x68,0x58,0xe6,0x04,0xd8,0x32,0x7b,0x9b,0x3c,0x10,0xc9,0x0c,0xa7};
	std::vector<byte> pbPlainText = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,0x29,0xbe,0xe1,0xd6,0x52,0x49,0xf1,0xe9,0xb3,0xdb,0x87,0x3e,0x24,0x0d,0x06,0x47};
	std::vector<byte> pbCipherText = {0x3f,0x1e,0x73,0xc3,0xdf,0xd5,0xa1,0x32,0x88,0x2f,0xe6,0x9d,0x99,0x6c,0xde,0x93,0x54,0x99,0x09,0x5d,0xde,0x68,0x99,0x5b,0x4d,0x70,0xf2,0x30,0x9f,0x2e,0xf1,0xb7};

    cout << "Plain Text: " << sdfToHex(pbPlainText) << endl;
    cout << "IV        : " << sdfToHex(pbIV) << endl;
    Key key = Key();
    key.setSymmetricKey(pbKeyValue);
    unsigned int cypherLen;
    std::vector<byte> cypher(32);
    unsigned int encryptCode  = provider.Encrypt(key, SM4_CBC ,pbIV.data(), pbPlainText.data(),
        32, cypher.data(), &cypherLen);
    if (encryptCode != SDR_OK) {
      cout << "Failed!!" <<endl;
      cout << provider.GetErrorMessage(encryptCode) <<endl;
    } else {
        cout << "Encrypt Result  : " << sdfToHex(cypher) << endl;
        cout << "Standard Result : " << sdfToHex(pbCipherText) << endl;
    }


    cout << "*****SM4 Decrypt****" << endl;
    cout << "Cipher Text: " << sdfToHex(pbPlainText) << endl;
    cout << "IV         : " << sdfToHex(originIV) << endl;
    std::vector<byte> plain(32);
    unsigned int plainlen;
    unsigned int decryptoCode = provider.Decrypt(
        key, SM4_CBC, originIV.data(), pbCipherText.data(), 32, plain.data(), &plainlen);
    if (decryptoCode != SDR_OK) {
      cout << "Failed!!" <<endl;
      cout << provider.GetErrorMessage(decryptoCode) <<endl;
    } else {
        cout << "Decrypt Result  : " << sdfToHex(plain) << endl;
        cout << "Standard Result : " << sdfToHex(pbPlainText) << endl;
    }

    cout << "*****generate Random Num****" << endl;
    unsigned int randomLength = 64;
    unsigned char ucRandom[1024+1] = {0};
    unsigned char Rand1[1024+1] = {0};
    if (provider.generateRandom(randomLength, ucRandom))
    {
        hextostr(ucRandom,64,Rand1);
        cout << "generate random number success :" << Rand1 << endl;
    }
    else
    {
        cout << "generate random number failed :" << endl;
    }
    

    cout << "******Prallel test******" << endl;
    vector<thread> callCardThread;
    for (int i = 0; i < sessionPoolRound; i++)
    {
        callCardThread.push_back(thread(callCard, loopRound));
    }
    for (auto iter = callCardThread.begin(); iter!= callCardThread.end(); iter++)
	{
		iter->join();  
	}
	cout << "prallel test finished " << endl;
    return 0;
}
