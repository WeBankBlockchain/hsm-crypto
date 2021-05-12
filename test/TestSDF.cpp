#include "csmsds.h"
#include <hsm/sdf/SDFCryptoProvider.h>
#include <iostream>
#include <string>
#include<thread>

using namespace std;
using namespace hsm;
using namespace hsm::sdf;


void callCard(int inum)
{
	SDFCryptoResult result = KeyGen(SM2);
}

int main(int, const char* argv[]){
    // Crypto provider 测试
    cout << "**************Begin Test, bash test-sdf-crypto [loopRound]************************"<<endl;
    SDFCryptoProvider& provider=SDFCryptoProvider::GetInstance();
    size_t loopRound = atoi(argv[1]);

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
    
    result = KeyGen(SM2);
    cout << "****KeyGen****" << endl;
    if (result.sdfErrorMessage != nullptr){
        cout << "Get error : " << result.sdfErrorMessage <<endl;
    }else{
        cout << "Get public key : " << result.publicKey << endl;
        cout << "Get private key : " << result.privateKey << endl;
    }

    SDFCryptoResult signResult = Sign(result.privateKey, SM2, sdfToHex(bHashStdResultVector));
    cout << "****Sign****" << endl;
    if (signResult.sdfErrorMessage != nullptr){
        cout << "Get error : " << signResult.sdfErrorMessage <<endl;
    }else{
        cout << "Get signature: " << signResult.signature << endl;
    }

    cout << "****Verify****" << endl;
    SDFCryptoResult verifyResult = Verify(
        result.publicKey, SM2, hsm::sdf::sdfToHex(bHashStdResultVector), signResult.signature);
    if (verifyResult.sdfErrorMessage != nullptr){
        cout << "Get error : " << verifyResult.sdfErrorMessage <<endl;
    }else{
        cout << "Get verify result: " << verifyResult.result << endl;
    }

    signResult = SignWithInternalKey(1, "123456", SM2, sdfToHex(bHashStdResultVector));
    cout << "****SignInternalKey****" << endl;
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
    SDFCryptoResult exportResult = ExportInternalPublicKey(2, SM2);
    cout << "Export public key: " << exportResult.publicKey << endl;


    cout << "*****SM4 Encrypt****" << endl;
    const std::vector<byte> pkv = {0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    std::shared_ptr<const std::vector<byte>> pbKeyValue =
        std::make_shared<const std::vector<byte>>(pkv);
    std::vector<byte> pbIV = {0xeb,0xee,0xc5,0x68,0x58,0xe6,0x04,0xd8,0x32,0x7b,0x9b,0x3c,0x10,0xc9,0x0c,0xa7};
	std::vector<byte> pbPlainText = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,0x29,0xbe,0xe1,0xd6,0x52,0x49,0xf1,0xe9,0xb3,0xdb,0x87,0x3e,0x24,0x0d,0x06,0x47};
	std::vector<byte> pbCipherText = {0x3f,0x1e,0x73,0xc3,0xdf,0xd5,0xa1,0x32,0x88,0x2f,0xe6,0x9d,0x99,0x6c,0xde,0x93,0x54,0x99,0x09,0x5d,0xde,0x68,0x99,0x5b,0x4d,0x70,0xf2,0x30,0x9f,0x2e,0xf1,0xb7};
    
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
        cout << "Result: " << sdfToHex(cypher) << endl;
        cout << "Stand : " << sdfToHex(pbCipherText) << endl;
    }


    cout << "*****SM4 Decrypt****" << endl;
    std::vector<byte> plain(32);
    unsigned int plainlen;
    unsigned int decryptoCode = provider.Decrypt(
        key, SM4_CBC, pbIV.data(), pbCipherText.data(), 32, plain.data(), &plainlen);
    if (decryptoCode != SDR_OK) {
      cout << "Failed!!" <<endl;
      cout << provider.GetErrorMessage(decryptoCode) <<endl;
    } else {
        cout << "Result: " << sdfToHex(plain) << endl;
        cout << "Stand : " << sdfToHex(pbPlainText) << endl;
    }

    vector<thread> callCardThread;
	for (int i = 0; i < loopRound; i++)
	{
		callCardThread.push_back(thread(callCard,i)); 
    }
    for (auto iter = callCardThread.begin(); iter!= callCardThread.end(); iter++)
	{
		iter->join();  
	}
	cout << "prallel test finished " << endl;
    return 0;
}