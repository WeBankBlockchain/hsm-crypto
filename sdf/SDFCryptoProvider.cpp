#include "SDFCryptoProvider.h"
#include "csmsds.h"
#include <cstring>
#include <list>
#include <iostream>
#include <stdio.h>
#include <cstdlib>
#include <string>
#include <vector>

using namespace std;
namespace dev
{
namespace crypto
{
SessionPool::SessionPool(int size, void* deviceHandle)
{
    m_size = size;
    m_deviceHandle = deviceHandle;
    for (int n = 0; n < m_size; n++)
    {
        SGD_HANDLE sessionHandle;
        SGD_RV sessionStatus = SDF_OpenSession(m_deviceHandle, &sessionHandle);
        if (sessionStatus != SDR_OK)
        {
            throw sessionStatus;
        }
        m_pool.push_back(sessionHandle);
    }
};
SessionPool::~SessionPool()
{
    auto iter = m_pool.begin();
    while (iter != m_pool.end())
    {
        SDF_CloseSession(*iter);
        ++iter;
    }
    m_size = 0;
};
void* SessionPool::GetSession()
{
    SGD_HANDLE session = NULL;
    if (m_size == 0)
    {
        SGD_HANDLE sessionHandle;
        SGD_RV sessionStatus = SDF_OpenSession(m_deviceHandle, &sessionHandle);
        if (sessionStatus != SDR_OK)
        {
            throw sessionStatus;
        }
        m_pool.push_back(sessionHandle);
        ++m_size;
    }
    session = m_pool.front();
    m_pool.pop_front();
    --m_size;
    return session;
};

void SessionPool::ReturnSession(void* session)
{
    m_pool.push_back(session);
    ++m_size;
};

SDFCryptoProvider::SDFCryptoProvider()
{
    SGD_RV deviceStatus = SDF_OpenDevice(&m_deviceHandle);
    if (deviceStatus != SDR_OK)
    {
        throw deviceStatus;
    }
    m_sessionPool = new SessionPool(10, m_deviceHandle);
}

SDFCryptoProvider::~SDFCryptoProvider()
{
    delete m_sessionPool;
    if (m_deviceHandle != NULL)
    {
        SDF_CloseDevice(m_deviceHandle);
    }
}

SDFCryptoProvider& SDFCryptoProvider::GetInstance()
{
    static SDFCryptoProvider instance;
    return instance;
}

unsigned int SDFCryptoProvider::Sign(Key const& key, AlgorithmType algorithm,
    unsigned char const* digest, unsigned int const digestLen, unsigned char* signature,
    unsigned int* signatureLen)
{
    switch (algorithm)
    {
    case SM2:
    {
        SGD_HANDLE sessionHandle = m_sessionPool->GetSession();
        SGD_RV signCode;
        if (key.IsInternalKey()){
            SGD_RV getAccessRightCode = SDF_GetPrivateKeyAccessRight(sessionHandle, key.Identifier(), (unsigned char *) key.Password(), (unsigned int)strlen(key.Password()));
            if (getAccessRightCode != SDR_OK){
                m_sessionPool->ReturnSession(sessionHandle);
                return signCode;
            }
            signCode = SDF_InternalSign_ECC(sessionHandle, key.Identifier(),(SGD_UCHAR*)digest, digestLen, (ECCSignature*)signature);
            SDF_ReleasePrivateKeyAccessRight(sessionHandle, key.Identifier());
        } else{
            ECCrefPrivateKey eccKey;
            eccKey.bits = 32 * 8;
            memcpy(eccKey.D, key.PrivateKey(), 32);
            signCode = SDF_ExternalSign_ECC(sessionHandle, SGD_SM2_1, &eccKey,
            (SGD_UCHAR*)digest, digestLen, (ECCSignature*)signature);
        }
        if (signCode != SDR_OK)
        {
            m_sessionPool->ReturnSession(sessionHandle);
            return signCode;
        }
        *signatureLen = 64;
        m_sessionPool->ReturnSession(sessionHandle);
        return SDR_OK;
    }
    default:
        return SDR_ALGNOTSUPPORT;
    }
}

unsigned int SDFCryptoProvider::KeyGen(AlgorithmType algorithm, Key* key)
{
    switch (algorithm)
    {
    case SM2:
    {
        ECCrefPublicKey pk;
        ECCrefPrivateKey sk;
        SGD_UINT32 keyLen = 256;

        SGD_HANDLE sessionHandle = m_sessionPool->GetSession();
        SGD_RV result = SDF_GenerateKeyPair_ECC(sessionHandle, SGD_SM2_3, keyLen, &pk, &sk);
        if (result != SDR_OK)
        {
            m_sessionPool->ReturnSession(sessionHandle);
            return result;
        }
        unsigned char pk_xy[64];
        memcpy(pk_xy,pk.x,32);
        memcpy(pk_xy+32,pk.y,32);
        key->setPrivateKey(sk.D, 32);
        key->setPublicKey(pk_xy, 64);
        m_sessionPool->ReturnSession(sessionHandle);
        return SDR_OK;
    }
    default:
        return SDR_ALGNOTSUPPORT;
    }
}

unsigned int SDFCryptoProvider::Hash(Key*, AlgorithmType algorithm, unsigned char const* message,
    unsigned int const messageLen, unsigned char* digest, unsigned int* digestLen)
{
    switch (algorithm)
    {
    case SM3:
    {
        SGD_HANDLE sessionHandle = m_sessionPool->GetSession();
        SGD_RV code = SDF_HashInit(sessionHandle, SGD_SM3, NULL, NULL, 0);
        if (code != SDR_OK)
        {
            m_sessionPool->ReturnSession(sessionHandle);
            return code;
        }

        code = SDF_HashUpdate(sessionHandle, (SGD_UCHAR*)message, messageLen);
        if (code != SDR_OK)
        {
            m_sessionPool->ReturnSession(sessionHandle);
            return code;
        }

        code = SDF_HashFinal(sessionHandle, digest, digestLen);
        if (code != SDR_OK)
        {
            m_sessionPool->ReturnSession(sessionHandle);
            return code;
        }
        m_sessionPool->ReturnSession(sessionHandle);
        return code;
    }
    default:
        return SDR_ALGNOTSUPPORT;
    }
}
unsigned int SDFCryptoProvider::HashWithZ(Key*, AlgorithmType algorithm, unsigned char const* zValue,
    unsigned int const zValueLen, unsigned char const* message, unsigned int const messageLen,
    unsigned char* digest, unsigned int* digestLen)
{
    switch (algorithm)
    {
    case SM3:
    {
        SGD_HANDLE sessionHandle = m_sessionPool->GetSession();
        SGD_RV code = SDF_HashInit(sessionHandle, SGD_SM3, NULL, NULL, 0);
        if (code != SDR_OK)
        {
            m_sessionPool->ReturnSession(sessionHandle);
            return code;
        }
        code = SDF_HashUpdate(sessionHandle, (SGD_UCHAR*)zValue, zValueLen);
        if (code != SDR_OK)
        {
            m_sessionPool->ReturnSession(sessionHandle);
            return code;
        }

        code = SDF_HashUpdate(sessionHandle, (SGD_UCHAR*)message, messageLen);
        if (code != SDR_OK)
        {
            m_sessionPool->ReturnSession(sessionHandle);
            return code;
        }

        code = SDF_HashFinal(sessionHandle, digest, digestLen);
        if (code != SDR_OK)
        {
            m_sessionPool->ReturnSession(sessionHandle);
            return code;
        }
        m_sessionPool->ReturnSession(sessionHandle);
        return code;
    }
    default:
        return SDR_ALGNOTSUPPORT;
    }
}

unsigned int SDFCryptoProvider::Verify(Key const& key, AlgorithmType algorithm,
    unsigned char const* digest, unsigned int const digestLen, unsigned char const* signature,
    const unsigned int signatureLen, bool* result)
{
    switch (algorithm)
    {
    case SM2:
    {
        if (signatureLen != 64)
        {
            return SDR_NOTSUPPORT;
        }
        SGD_HANDLE sessionHandle = m_sessionPool->GetSession();
        ECCSignature eccSignature;
        memcpy(eccSignature.r, signature, 32);
        memcpy(eccSignature.s, signature + 32, 32);
        SGD_RV code;

        if (key.IsInternalKey()){
            code = SDF_InternalVerify_ECC(sessionHandle, key.Identifier(), (SGD_UCHAR*)digest, digestLen, &eccSignature);
        } else{
            ECCrefPublicKey eccKey;
            eccKey.bits = 32 * 8;
            memcpy(eccKey.x, key.PublicKey(), 32);
            memcpy(eccKey.y, key.PublicKey() + 32, 32);
            code = SDF_ExternalVerify_ECC(
            sessionHandle, SGD_SM2_1, &eccKey, (SGD_UCHAR*)digest, digestLen, &eccSignature);
        }
        if (code == SDR_OK)
        {
            *result = true;
        }
        else
        {
            *result = false;
        }
        m_sessionPool->ReturnSession(sessionHandle);
        return code;
    }
    default:
        return SDR_ALGNOTSUPPORT;
    }
}
unsigned int
SDFCryptoProvider::ExportInternalPublicKey(Key &key, AlgorithmType algorithm) {
  switch (algorithm) {
  case SM2: {
    if (!key.IsInternalKey()) {
      return SDR_ALGNOTSUPPORT;
    }
    ECCrefPublicKey pk;
    SGD_HANDLE sessionHandle = m_sessionPool->GetSession();
    SGD_RV result =
        SDF_ExportSignPublicKey_ECC(sessionHandle, key.Identifier(), &pk);
    if (result != SDR_OK) {
      m_sessionPool->ReturnSession(sessionHandle);
      return result;
    }
    unsigned char pk_xy[64];
    memcpy(pk_xy, pk.x, 32);
    memcpy(pk_xy + 32, pk.y, 32);
    key.setPublicKey(pk_xy, 64);
    m_sessionPool->ReturnSession(sessionHandle);
    return result;
  }
  default:
    return SDR_ALGNOTSUPPORT;
  }
}

char * SDFCryptoProvider::GetErrorMessage(unsigned int code)
{
    switch (code)
    {
    case SDR_OK:
        return (char *)"success";
    case SDR_UNKNOWERR:
        return (char *)"unknown error";
    case SDR_NOTSUPPORT:
        return (char *)"not support";
    case SDR_COMMFAIL:
        return (char *)"communication failed";
    case SDR_OPENDEVICE:
        return (char *)"failed open device";
    case SDR_OPENSESSION:
        return (char *)"failed open session";
    case SDR_PARDENY:
        return (char *)"permission deny";
    case SDR_KEYNOTEXIST:
        return (char *)"key not exit";
    case SDR_ALGNOTSUPPORT:
        return (char *)"algorithm not support";
    case SDR_ALGMODNOTSUPPORT:
        return (char *)"algorithm not support mode";
    case SDR_PKOPERR:
        return (char *)"public key calculate error";
    case SDR_SKOPERR:
        return (char *)"private key calculate error";
    case SDR_SIGNERR:
        return (char *)"signature error";
    case SDR_VERIFYERR:
        return (char *)"verify signature error";
    case SDR_SYMOPERR:
        return (char *)"symmetric crypto calculate error";
    case SDR_STEPERR:
        return (char *)"step error";
    case SDR_FILESIZEERR:
        return (char *)"file size error";
    case SDR_FILENOEXIST:
        return (char *)"file not exist";
    case SDR_FILEOFSERR:
        return (char *)"file offset error";
    case SDR_KEYTYPEERR:
        return (char *)"key type not right";
    case SDR_KEYERR:
        return (char *)"key error";
    default:
	std::string err = "unkown code " + std::to_string(code);
	char * c_err = new char[err.length()+1];
	strcpy(c_err,err.c_str());
	return c_err;
    }
}

SDFCryptoResult KeyGen(AlgorithmType algorithm){
    try{
        SDFCryptoProvider& provider = SDFCryptoProvider::GetInstance();
        Key key=Key();
        unsigned int code = provider.KeyGen(algorithm,&key);
        if (code != SDR_OK){
            return makeResult(nullptr,nullptr,nullptr,false,nullptr,code,nullptr);
        }else{
            return makeResult(nullptr,toHex(key.PublicKey(),key.PublicKeyLen()),toHex(key.PrivateKey(),key.PrivateKeyLen()),false,nullptr,code,nullptr);
        } 
    }catch(const char* e){
        return makeResult(nullptr,nullptr,nullptr,false,nullptr,SDR_OK,(char*)e);
    }
}
SDFCryptoResult Sign(char * privateKey, AlgorithmType algorithm, char const* digest){
    try{
        Key key = Key();
        key.setPrivateKey(fromHex(privateKey).data(),32);
        SearchData(fromHex(privateKey).data(),32,16);
        SearchData(fromHex((char *)digest).data(),32,16);
        SDFCryptoProvider& provider = SDFCryptoProvider::GetInstance();
        unsigned char * signature = (unsigned char *)malloc(64*sizeof(char));
        unsigned int len;
        unsigned int code = provider.Sign(key,algorithm,fromHex((char *)digest).data(),getHexByteLen((char *)digest),signature,&len);
        if (code != SDR_OK){
            return makeResult(nullptr,nullptr,nullptr,false,nullptr,code,nullptr);
        }else{
            return makeResult(toHex(signature,len),nullptr,nullptr,false,nullptr,code,nullptr);
        } 
    }catch(const char* e){
        return makeResult(nullptr,nullptr,nullptr,false,nullptr,SDR_OK,(char*)e);
    }    
}
SDFCryptoResult SignWithInternalKey(unsigned int keyIndex, char *password,
                                    AlgorithmType algorithm,
                                    char const *digest) {
  try {
    Key key = Key(keyIndex, password);
    SDFCryptoProvider &provider = SDFCryptoProvider::GetInstance();
    unsigned char *signature = (unsigned char *)malloc(64 * sizeof(char));
    unsigned int len;
    unsigned int code =
        provider.Sign(key, algorithm, fromHex((char *)digest).data(),
                      getHexByteLen((char *)digest), signature, &len);
    if (code != SDR_OK) {
      return makeResult(nullptr, nullptr, nullptr, false, nullptr, code,
                        nullptr);
    } else {
      return makeResult(toHex(signature, len), nullptr, nullptr, false, nullptr,
                        code, nullptr);
    }
  } catch (const char *e) {
    return makeResult(nullptr, nullptr, nullptr, false, nullptr, SDR_OK,
                      (char *)e);
  }
}
SDFCryptoResult Verify(char * publicKey, AlgorithmType algorithm, char const* digest, char const* signature){
    try{
        Key key = Key();
        key.setPublicKey(fromHex(publicKey).data(),64);
        SearchData(fromHex(publicKey).data(),64,16);
        SearchData(fromHex((char *)signature).data(),64,16);
        SearchData(fromHex((char *)digest).data(),32,16);
        SDFCryptoProvider& provider = SDFCryptoProvider::GetInstance();
        bool isValid;
        unsigned int code = provider.Verify(key,algorithm,fromHex((char *)digest).data(),getHexByteLen((char *)digest),fromHex((char *)signature).data(),getHexByteLen((char*)signature),&isValid);
        return makeResult(nullptr,nullptr,nullptr,isValid,nullptr,code,nullptr);
    }catch(const char* e){
        return makeResult(nullptr,nullptr,nullptr,false,nullptr,SDR_OK,(char*)e);
    }   
}

SDFCryptoResult VerifyWithInternalKey(unsigned int keyIndex,
                                      AlgorithmType algorithm,
                                      char const *digest,
                                      char const *signature) {
  try {
    Key key = Key(keyIndex);
    SearchData(fromHex((char *)signature).data(), 64, 16);
    SearchData(fromHex((char *)digest).data(), 32, 16);
    SDFCryptoProvider &provider = SDFCryptoProvider::GetInstance();
    bool isValid;
    unsigned int code = provider.Verify(
        key, algorithm, fromHex((char *)digest).data(),
        getHexByteLen((char *)digest), fromHex((char *)signature).data(),
        getHexByteLen((char *)signature), &isValid);
    return makeResult(nullptr, nullptr, nullptr, isValid, nullptr, code,
                      nullptr);
  } catch (const char *e) {
    return makeResult(nullptr, nullptr, nullptr, false, nullptr, SDR_OK,
                      (char *)e);
  }
}

SDFCryptoResult Hash(char * publicKey, AlgorithmType algorithm, char const* message){
    try{
        SDFCryptoProvider& provider = SDFCryptoProvider::GetInstance();
        bool isValid;
        unsigned char hashResult[32];
        unsigned int len;
        unsigned int code = provider.Hash(nullptr,algorithm,fromHex((char *)message).data(),getHexByteLen((char *)message),hashResult,&len);
        return makeResult(nullptr,nullptr,nullptr,false,toHex(hashResult,32),code,nullptr);
    }catch(const char* e){
        return makeResult(nullptr,nullptr,nullptr,false,nullptr,SDR_OK,(char*)e);
    }   
    
}



SDFCryptoResult HashWithZ(char * key, AlgorithmType algorithm, char const* message){
    try{
        SDFCryptoProvider& provider = SDFCryptoProvider::GetInstance();
        bool isValid;
        unsigned char hashResult[32];
        unsigned int len;
        unsigned int code = provider.Hash(nullptr,algorithm,fromHex((char *)message).data(),getHexByteLen((char *)message),hashResult,&len);
        return makeResult(nullptr,nullptr,nullptr,false,toHex(hashResult,32),code,nullptr);
    }catch(const char* e){
        return makeResult(nullptr,nullptr,nullptr,false,nullptr,SDR_OK,(char*)e);
    }
}

SDFCryptoResult ExportInternalPublicKey(unsigned int keyIndex,
                                        AlgorithmType algorithm) {
  try {
    SDFCryptoProvider &provider = SDFCryptoProvider::GetInstance();
    Key key = Key(keyIndex);
    unsigned int code = provider.ExportInternalPublicKey(key, SM2);
    if (code == SDR_OK) {
      return makeResult(nullptr, toHex(key.PublicKey(), 64), nullptr, false,
                        nullptr, code, nullptr);
    } else {
      return makeResult(nullptr, nullptr, nullptr, false, nullptr, code,
                        nullptr);
    }
  } catch (const char *e) {
    return makeResult(nullptr, nullptr, nullptr, false, nullptr, SDR_OK,
                      (char *)e);
  }
}

SDFCryptoResult makeResult(char * signature,char * publicKey,char * privateKey,bool result,char * hash,unsigned int code,char* msg){
    SDFCryptoResult cryptoResult;
    cryptoResult.signature = signature;
    cryptoResult.publicKey = publicKey;
    cryptoResult.privateKey = privateKey;
    cryptoResult.result = result;
    cryptoResult.hash = hash;
    if(code != SDR_OK){
        cryptoResult.sdfErrorMessage = SDFCryptoProvider::GetErrorMessage(code);
    }else{
        cryptoResult.sdfErrorMessage = nullptr;
    }
    if (msg != nullptr){
        cryptoResult.sdfErrorMessage = msg;
    }
    return cryptoResult;
}
char* toHex(unsigned char *data, int len)
{
    static char const* hexdigits = "0123456789abcdef";
    std::string hex(len * 2, '0');
    int position = 0;
    for (int i = 0; i < len; i++)
    {
        hex[position++] = hexdigits[(data[i] >> 4) & 0x0f];
        hex[position++] = hexdigits[data[i] & 0x0f];
    }
    char * c_hex = new char[len * 2 +1];
    strcpy(c_hex,hex.c_str());
    return c_hex;
}

std::vector<uint8_t> fromHex(char * hexString){
    size_t len = strlen(hexString);
    unsigned s = (len>= 2 && hexString[0] == '0' && hexString[1] == 'x') ? 2 : 0;
    std::vector<uint8_t> ret;
    ret.reserve((len - s + 1) / 2);
    if(len%2){
        int h = fromHexChar(hexString[s++]);
        if (h != -1)
            ret.push_back(h);
        else
            throw "bad hex string";
    }
    for (unsigned i = s; i < len; i += 2)
    {
        int h = fromHexChar(hexString[i]);
        int l = fromHexChar(hexString[i + 1]);

        if (h != -1 && l != -1){
            ret.push_back((uint8_t)(h * 16 + l));
        }else{
            throw "bad hex string";
        }  
    }
    return ret;
}

unsigned int getHexByteLen(char * hexString){
    size_t len = strlen(hexString);
    unsigned s = (len>= 2 && hexString[0] == '0' && hexString[1] == 'x') ? 2 : 0;
    return (len - s + 1) / 2;
}

int fromHexChar(char _i)
{
    if (_i >= '0' && _i <= '9')
        return _i - '0';
    if (_i >= 'a' && _i <= 'f')
        return _i - 'a' + 10;
    if (_i >= 'A' && _i <= 'F')
        return _i - 'A' + 10;
    return -1;
}

int PrintData(char *itemName, unsigned char *sourceData, unsigned int dataLength, unsigned int rowCount)
{
	int i, j;
	
	if((sourceData == NULL) || (rowCount == 0) || (dataLength == 0))
		return -1;
	
	if(itemName != NULL)
		printf("%s[%d]:\n", itemName, dataLength);
	
	for(i=0; i<(int)(dataLength/rowCount); i++)
	{
		printf("%08x  ",i * rowCount);

		for(j=0; j<(int)rowCount; j++)
		{
			printf("%02x ", *(sourceData + i*rowCount + j));
		}

		printf("\n");
	}

	if (!(dataLength % rowCount))
		return 0;
	
	printf("%08x  ", (dataLength/rowCount) * rowCount);

	for(j=0; j<(int)(dataLength%rowCount); j++)
	{
		printf("%02x ",*(sourceData + (dataLength/rowCount)*rowCount + j));
	}

	printf("\n");

	return 0;
}

int SearchData(unsigned char *sourceData, unsigned int dataLength, unsigned int rowCount)
{
	int i, j;
	
	if((sourceData == NULL) || (rowCount == 0) || (dataLength == 0))
		return -1;
	for(i=0; i<(int)(dataLength/rowCount); i++)
	{
		i * rowCount;
		for(j=0; j<(int)rowCount; j++)
		{
			*(sourceData + i*rowCount + j);
		}
	}
	return 0;
}

}  // namespace crypto
}  // namespace dev
