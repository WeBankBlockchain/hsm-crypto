#include "gmt0018.h"
#include <hsm/sdf/SDFCryptoProvider.h>
#include <exception>
#include <iostream>
#include <string>
#include <thread>

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
            std::cout << provider.GetErrorMessage(code) << std::endl;
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
    std::cout << "**************Begin Test, bash test-sdf-crypto [sessionPoolSize] "
            "[loopRound]************************"
         << std::endl;
    size_t sessionPoolRound = atoi(argv[1]);
    size_t loopRound = atoi(argv[2]);
    try
    {
        SDFCryptoProvider& provider = SDFCryptoProvider::GetInstance(sessionPoolRound);
    }
    catch (const std::exception& e)
    {
        std::cout << "error occured, info: " << e.what() << std::endl;
        exit(1);
    }
    SDFCryptoProvider& provider = SDFCryptoProvider::GetInstance(sessionPoolRound);

    // Make hash
    std::cout << "**************Make SM3 Hash************************"<< std::endl;
    std::vector<byte> bHashVector = {0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,
                                0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,
                                0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,
                                0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64};

    std::vector<byte> bHashStdResultVector = {0xde,0xbe,0x9f,0xf9,0x22,0x75,0xb8,0xa1,0x38,0x60,0x48,0x89,0xc1,0x8e,0x5a,0x4d,
                                    0x6f,0xdb,0x70,0xe5,0x38,0x7e,0x57,0x65,0x29,0x3d,0xcb,0xa3,0x9c,0x0c,0x57,0x32};
    SDFCryptoResult result = Hash(nullptr, SM3, sdfToHex(bHashVector));
    if (result.sdfErrorMessage != nullptr){
        std::cout << "Get error : " << result.sdfErrorMessage << std::endl;
    }else{
        std::cout << "Get Hash : " << result.hash << std::endl;

        std::cout << "Standard : " << sdfToHex(bHashStdResultVector) << std::endl;
    }

    std::cout << "****KeyGen****" << std::endl;
    result = KeyGen(SM2);
    if (result.sdfErrorMessage != nullptr){
        std::cout << "Get error : " << result.sdfErrorMessage << std::endl;
    }else{
        std::cout << "Get public key : " << result.publicKey << std::endl;
        std::cout << "Get private key : " << result.privateKey << std::endl;
    }
    
    std::cout << "**************Make SM2_SM3 Hash************************"<< std::endl;
    SDFCryptoResult sm2_sm3_result = Hash(result.publicKey, SM3, sdfToHex(bHashVector));
    if (sm2_sm3_result.sdfErrorMessage != nullptr)
    {
        std::cout << "Get error : " << sm2_sm3_result.sdfErrorMessage << std::endl;
    }
    else
    {
        std::cout << "SM2_SM3 : " << sm2_sm3_result.hash << std::endl;
    }

    std::cout << "****Sign****" << std::endl;
    SDFCryptoResult signResult;
    signResult = Sign(result.privateKey, SM2, sdfToHex(bHashStdResultVector));
    if (signResult.sdfErrorMessage != nullptr){
        std::cout << "Get error : " << signResult.sdfErrorMessage << std::endl;
    }else{
        std::cout << "Get signature: " << signResult.signature << std::endl;
    }

    std::cout << "****Verify****" << std::endl;
    SDFCryptoResult verifyResult;
    verifyResult = Verify(
        result.publicKey, SM2, hsm::sdf::sdfToHex(bHashStdResultVector), signResult.signature);
    if (verifyResult.sdfErrorMessage != nullptr){
        std::cout << "Get error : " << verifyResult.sdfErrorMessage << std::endl;
    }else{
        std::cout << "Get verify result: " << verifyResult.result << std::endl;
    }

    std::cout << "****SignInternalKey****" << std::endl;
    signResult = SignWithInternalKey(1, "12345678", SM2, sdfToHex(bHashStdResultVector));
    if (signResult.sdfErrorMessage != nullptr){
        std::cout << "Get error : " << signResult.sdfErrorMessage << std::endl;
    }else{
        std::cout << "Get signature: " << signResult.signature << std::endl;
    }

    std::cout << "****VerifyInternalKey****" << std::endl;
    verifyResult = VerifyWithInternalKey(
        1, SM2, (const char*)sdfToHex(bHashStdResultVector), signResult.signature);
    if (verifyResult.sdfErrorMessage != nullptr){
        std::cout << "Get error : " << verifyResult.sdfErrorMessage << std::endl;
    }else{
        std::cout << "Get verify result: " << verifyResult.result << std::endl;
    }

    std::cout << "*****ExportInternalPublicKey****" << std::endl;
    SDFCryptoResult exportResult = ExportInternalPublicKey(1, SM2);
    std::cout << "Export public key: " << exportResult.publicKey << std::endl;


    std::cout << "*****SM4 Encrypt****" << std::endl;
    const std::vector<byte> pkv = {0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    std::shared_ptr<const std::vector<byte>> pbKeyValue =
        std::make_shared<const std::vector<byte>>(pkv);
    std::vector<byte> originIV = {0xeb, 0xee, 0xc5, 0x68, 0x58, 0xe6, 0x04, 0xd8, 0x32, 0x7b, 0x9b,
        0x3c, 0x10, 0xc9, 0x0c, 0xa7};
    std::vector<byte> pbIV = {0xeb,0xee,0xc5,0x68,0x58,0xe6,0x04,0xd8,0x32,0x7b,0x9b,0x3c,0x10,0xc9,0x0c,0xa7};
	std::vector<byte> pbPlainText = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,0x29,0xbe,0xe1,0xd6,0x52,0x49,0xf1,0xe9,0xb3,0xdb,0x87,0x3e,0x24,0x0d,0x06,0x47};
	std::vector<byte> pbCipherText = {0x3f,0x1e,0x73,0xc3,0xdf,0xd5,0xa1,0x32,0x88,0x2f,0xe6,0x9d,0x99,0x6c,0xde,0x93,0x54,0x99,0x09,0x5d,0xde,0x68,0x99,0x5b,0x4d,0x70,0xf2,0x30,0x9f,0x2e,0xf1,0xb7};

    std::cout << "Plain Text: " << sdfToHex(pbPlainText) << std::endl;
    std::cout << "IV        : " << sdfToHex(pbIV) << std::endl;
    Key key = Key();
    key.setSymmetricKey(pbKeyValue);
    unsigned int cypherLen;
    std::vector<byte> cypher(32);
    unsigned int encryptCode  = provider.Encrypt(key, SM4_CBC ,pbIV.data(), pbPlainText.data(),
        32, cypher.data(), &cypherLen);
    if (encryptCode != SDR_OK) {
      std::cout << "Failed!!" << std::endl;
      std::cout << provider.GetErrorMessage(encryptCode) << std::endl;
    } else {
        std::cout << "Encrypt Result  : " << sdfToHex(cypher) << std::endl;
        std::cout << "Standard Result : " << sdfToHex(pbCipherText) << std::endl;
    }


    std::cout << "*****SM4 Decrypt****" << std::endl;
    std::cout << "Cipher Text: " << sdfToHex(pbPlainText) << std::endl;
    std::cout << "IV         : " << sdfToHex(originIV) << std::endl;
    std::vector<byte> plain(32);
    unsigned int plainlen;
    unsigned int decryptoCode = provider.Decrypt(
        key, SM4_CBC, originIV.data(), pbCipherText.data(), 32, plain.data(), &plainlen);
    if (decryptoCode != SDR_OK) {
      std::cout << "Failed!!" << std::endl;
      std::cout << provider.GetErrorMessage(decryptoCode) << std::endl;
    } else {
        std::cout << "Decrypt Result  : " << sdfToHex(plain) << std::endl;
        std::cout << "Standard Result : " << sdfToHex(pbPlainText) << std::endl;
    }

    std::cout << "*****generate Random Num****" << std::endl;
    unsigned int randomLength = 64;
    unsigned char ucRandom[1024+1] = {0};
    unsigned char Rand1[1024+1] = {0};
    if (provider.generateRandom(randomLength, ucRandom))
    {
        hextostr(ucRandom,64,Rand1);
        std::cout << "generate random number success :" << Rand1 << std::endl;
    }
    else
    {
        std::cout << "generate random number failed :" << std::endl;
    }
    

    std::cout << "******Prallel test******" << std::endl;
    std::vector<std::thread> callCardThread;
    for (int i = 0; i < sessionPoolRound; i++)
    {
        callCardThread.push_back(std::thread(callCard, loopRound));
    }
    for (auto iter = callCardThread.begin(); iter!= callCardThread.end(); iter++)
	{
		iter->join();  
	}
	std::cout << "prallel test finished " << std::endl;
    return 0;
}
