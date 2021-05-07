#include "SDFCryptoProvider.h"
#include "../Common.h"
#include "csmsds.h"
#include <stdio.h>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <list>
#include <memory>
#include <string>
#include <vector>
#include<condition_variable>
using namespace std;
using namespace hsm;
namespace hsm
{
namespace sdf
{
SessionPool::SessionPool(int size, void* deviceHandle)
{
    if(size <= 0){
        throw "HSM device session pool size should be bigger than 0";
    }
    m_size = size;
    m_deviceHandle = deviceHandle;
    for (size_t n = 0; n < m_size; n++)
    {
        SGD_HANDLE sessionHandle;
        SGD_RV sessionStatus = SDF_OpenSession(m_deviceHandle, &sessionHandle);
        if (sessionStatus != SDR_OK)
        {
            throw sessionStatus;
        }
        m_pool.push_back(sessionHandle);
    }
}
SessionPool::~SessionPool()
{
    for(auto session : m_pool) {  
        SDF_CloseSession(session); 
    } 
}
void* SessionPool::GetSession()
{
    std::lock_guard<std::mutex> l(mut);
    SGD_HANDLE session = NULL;
    if (m_pool.size() == 0)
    {
        SGD_HANDLE sessionHandle;
        SGD_RV sessionStatus = SDF_OpenSession(m_deviceHandle, &sessionHandle);
        if (sessionStatus != SDR_OK)
        {
            throw sessionStatus;
        }
        m_pool.push_back(sessionHandle);
    }
    session = m_pool.front();
    m_pool.pop_front();
    return session;
}

void SessionPool::SetPoolSize(int size){
    if(size <= 0){
        return;
    }
    m_size = size;
}
void SessionPool::ReturnSession(void* session)
{
    std::lock_guard<std::mutex> l(mut);
    m_pool.push_back(session);
    while (m_pool.size() > m_size)
    {
        SGD_HANDLE session = m_pool.front();
        m_pool.pop_front();
        SDF_CloseSession(session);
    }
}

SDFCryptoProvider::SDFCryptoProvider()
{
    SGD_RV deviceStatus = SDF_OpenDevice(&m_deviceHandle);
    if (deviceStatus != SDR_OK)
    {
        throw deviceStatus;
    }
    m_sessionPool = new SessionPool(10, m_deviceHandle);
}

SDFCryptoProvider::SDFCryptoProvider(int sessionPoolSize)
{
    SGD_RV deviceStatus = SDF_OpenDevice(&m_deviceHandle);
    if (deviceStatus != SDR_OK)
    {
        throw deviceStatus;
    }
    m_sessionPool = new SessionPool(sessionPoolSize, m_deviceHandle);
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

SDFCryptoProvider& SDFCryptoProvider::GetInstance(int sessionPoolSize)
{
    GetInstance().m_sessionPool->SetPoolSize(sessionPoolSize);
    return GetInstance();
}

unsigned int SDFCryptoProvider::Sign(Key const& key, AlgorithmType algorithm,
    unsigned char const* digest, unsigned int digestLen, unsigned char* signature,
    unsigned int* signatureLen)
{
    switch (algorithm)
    {
    case SM2:
    {
        SGD_HANDLE sessionHandle = m_sessionPool->GetSession();
        SGD_RV signCode;
        if (key.isInternalKey())
        {
            SGD_RV getAccessRightCode =
                SDF_GetPrivateKeyAccessRight(sessionHandle, key.identifier(),
                    (SGD_UCHAR*)key.password()->data(), (SGD_UINT32)key.password()->size());
            if (getAccessRightCode != SDR_OK)
            {
                m_sessionPool->ReturnSession(sessionHandle);
                return getAccessRightCode;
            }
            signCode = SDF_InternalSign_ECC(sessionHandle, key.identifier(), (SGD_UCHAR*)digest,
                digestLen, (ECCSignature*)signature);
            SDF_ReleasePrivateKeyAccessRight(sessionHandle, key.identifier());
        }
        else
        {
            ECCrefPrivateKey eccKey;
            eccKey.bits = 32 * 8;
            memcpy(eccKey.D, key.privateKey()->data(), 32);
            signCode = SDF_ExternalSign_ECC(sessionHandle, SGD_SM2_1, &eccKey, (SGD_UCHAR*)digest,
                digestLen, (ECCSignature*)signature);
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

        std::shared_ptr<const std::vector<byte>> privKey =
            std::make_shared<const std::vector<byte>>((byte*)sk.D, (byte*)sk.D + 32);

        std::shared_ptr<vector<byte>> pubKey = std::make_shared<vector<byte>>();
        pubKey->reserve(32 + 32);
        pubKey->insert(pubKey->end(), (byte*)pk.x, (byte*)pk.x + 32);
        pubKey->insert(pubKey->end(), (byte*)pk.y, (byte*)pk.y + 32);

        key->setPrivateKey(privKey);
        key->setPublicKey(pubKey);
        m_sessionPool->ReturnSession(sessionHandle);
        return SDR_OK;
    }
    default:
        return SDR_ALGNOTSUPPORT;
    }
}

unsigned int SDFCryptoProvider::Hash(Key*, AlgorithmType algorithm, unsigned char const* message,
    unsigned int messageLen, unsigned char* digest, unsigned int* digestLen)
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
unsigned int SDFCryptoProvider::HashWithZ(Key*, AlgorithmType algorithm,
    unsigned char const* zValue, unsigned int zValueLen, unsigned char const* message,
    unsigned int messageLen, unsigned char* digest, unsigned int* digestLen)
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
    unsigned char const* digest, unsigned int digestLen, unsigned char const* signature,
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

        if (key.isInternalKey())
        {
            code = SDF_InternalVerify_ECC(
                sessionHandle, key.identifier(), (SGD_UCHAR*)digest, digestLen, &eccSignature);
        }
        else
        {
            ECCrefPublicKey eccKey;
            eccKey.bits = 32 * 8;
            memcpy(eccKey.x, key.publicKey()->data(), 32);
            memcpy(eccKey.y, key.publicKey()->data() + 32, 32);
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
unsigned int SDFCryptoProvider::ExportInternalPublicKey(Key& key, AlgorithmType algorithm)
{
    switch (algorithm)
    {
    case SM2:
    {
        if (!key.isInternalKey())
        {
            return SDR_ALGNOTSUPPORT;
        }
        ECCrefPublicKey pk;
        SGD_HANDLE sessionHandle = m_sessionPool->GetSession();
        SGD_RV result = SDF_ExportSignPublicKey_ECC(sessionHandle, key.identifier(), &pk);
        if (result != SDR_OK)
        {
            m_sessionPool->ReturnSession(sessionHandle);
            return result;
        }

        std::shared_ptr<vector<byte>> pubKey = std::make_shared<vector<byte>>();
        pubKey->reserve(32 + 32);
        pubKey->insert(pubKey->end(), (byte*)pk.x, (byte*)pk.x + 32);
        pubKey->insert(pubKey->end(), (byte*)pk.y, (byte*)pk.y + 32);

        key.setPublicKey(pubKey);
        m_sessionPool->ReturnSession(sessionHandle);
        return result;
    }
    default:
        return SDR_ALGNOTSUPPORT;
    }
}

unsigned int SDFCryptoProvider::Encrypt(Key const& key, AlgorithmType algorithm, unsigned char* iv,
    unsigned char const* plantext, unsigned int plantextLen, unsigned char* cyphertext,
    unsigned int* cyphertextLen)
{
    switch (algorithm)
    {
    case SM4_CBC:
    {
        SGD_HANDLE sessionHandle = m_sessionPool->GetSession();
        SGD_HANDLE keyHandler;
        SGD_RV importResult = SDF_ImportKey(sessionHandle, (SGD_UCHAR*)key.symmetrickey()->data(),
            key.symmetrickey()->size(), &keyHandler);
        if (!importResult == SDR_OK)
        {
            m_sessionPool->ReturnSession(sessionHandle);
            return importResult;
        }
        SGD_RV result = SDF_Encrypt(sessionHandle, keyHandler, SGD_SM4_CBC, (SGD_UCHAR*)iv,
            (SGD_UCHAR*)plantext, plantextLen, (SGD_UCHAR*)cyphertext, cyphertextLen);
        SDF_DestroyKey(sessionHandle, keyHandler);
        m_sessionPool->ReturnSession(sessionHandle);
        return result;
    }
    default:
        return SDR_ALGNOTSUPPORT;
    }
}

unsigned int SDFCryptoProvider::Decrypt(Key const& key, AlgorithmType algorithm, unsigned char* iv,
    unsigned char const* cyphertext, unsigned int cyphertextLen, unsigned char* plantext,
    unsigned int* plantextLen)
{
    switch (algorithm)
    {
    case SM4_CBC:
    {
        SGD_HANDLE sessionHandle = m_sessionPool->GetSession();
        SGD_HANDLE keyHandler;
        SGD_RV importResult = SDF_ImportKey(sessionHandle, (SGD_UCHAR*)key.symmetrickey()->data(),
            key.symmetrickey()->size(), &keyHandler);
        if (!importResult == SDR_OK)
        {
            m_sessionPool->ReturnSession(sessionHandle);
            return importResult;
        }
        SGD_RV result = SDF_Decrypt(sessionHandle, keyHandler, SGD_SM4_CBC, (SGD_UCHAR*)iv,
            (SGD_UCHAR*)cyphertext, cyphertextLen, (SGD_UCHAR*)plantext, plantextLen); 
        SDF_DestroyKey(sessionHandle, keyHandler);
        m_sessionPool->ReturnSession(sessionHandle);
        return result;
    }
    default:
        return SDR_ALGNOTSUPPORT;
    }
}

char* SDFCryptoProvider::GetErrorMessage(unsigned int code)
{
    switch (code)
    {
    case SDR_OK:
        return (char*)"success";
    case SDR_UNKNOWERR:
        return (char*)"unknown error";
    case SDR_NOTSUPPORT:
        return (char*)"not support";
    case SDR_COMMFAIL:
        return (char*)"communication failed";
    case SDR_OPENDEVICE:
        return (char*)"failed open device";
    case SDR_OPENSESSION:
        return (char*)"failed open session";
    case SDR_PARDENY:
        return (char*)"permission deny";
    case SDR_KEYNOTEXIST:
        return (char*)"key not exit";
    case SDR_ALGNOTSUPPORT:
        return (char*)"algorithm not support";
    case SDR_ALGMODNOTSUPPORT:
        return (char*)"algorithm not support mode";
    case SDR_PKOPERR:
        return (char*)"public key calculate error";
    case SDR_SKOPERR:
        return (char*)"private key calculate error";
    case SDR_SIGNERR:
        return (char*)"signature error";
    case SDR_VERIFYERR:
        return (char*)"verify signature error";
    case SDR_SYMOPERR:
        return (char*)"symmetric crypto calculate error";
    case SDR_STEPERR:
        return (char*)"step error";
    case SDR_FILESIZEERR:
        return (char*)"file size error";
    case SDR_FILENOEXIST:
        return (char*)"file not exist";
    case SDR_FILEOFSERR:
        return (char*)"file offset error";
    case SDR_KEYTYPEERR:
        return (char*)"key type not right";
    case SDR_KEYERR:
        return (char*)"key error";
    default:
        std::string err = "unkown code " + std::to_string(code);
        char* c_err = new char[err.length() + 1];
        strcpy(c_err, err.c_str());
        return c_err;
    }
}

SDFCryptoResult KeyGen(AlgorithmType algorithm)
{
    switch (algorithm)
    {
    case SM2:
        try
        {
            SDFCryptoProvider& provider = SDFCryptoProvider::GetInstance();
            Key key = Key();
            unsigned int code = provider.KeyGen(algorithm, &key);
            if (code != SDR_OK)
            {
                return makeResult(nullptr, nullptr, nullptr, false, nullptr, code, nullptr);
            }
            else
            {
                return makeResult(nullptr, toHex(*key.publicKey().get()),
                    toHex(*key.privateKey().get()), false, nullptr, code, nullptr);
            }
        }
        catch (const char* e)
        {
            return makeResult(nullptr, nullptr, nullptr, false, nullptr, SDR_OK, (char*)e);
        }
    default:
        return makeResult(nullptr, nullptr, nullptr, false, nullptr, SDR_NOTSUPPORT,
            (char*)"algrithum not support yet");
    }
}
SDFCryptoResult Sign(char* privateKey, AlgorithmType algorithm, char const* digest)
{
    switch (algorithm)
    {
    case SM2:
        try
        {
            Key key = Key();
            const vector<byte> sk = fromHex(privateKey);
            std::shared_ptr<const vector<byte>> privKey =
                std::make_shared<const std::vector<byte>>((byte*)sk.data(), (byte*)sk.data() + 32);
            key.setPrivateKey(privKey);
            SDFCryptoProvider& provider = SDFCryptoProvider::GetInstance();
            std::vector<byte> signature(64);
            // unsigned char* signature = (unsigned char*)malloc(64 * sizeof(char));
            unsigned int len;
            unsigned int code = provider.Sign(key, algorithm, fromHex((char*)digest).data(),
                getHexByteLen((char*)digest), signature.data(), &len);
            if (code != SDR_OK)
            {
                return makeResult(nullptr, nullptr, nullptr, false, nullptr, code, nullptr);
            }
            else
            {
                return makeResult(
                    toHex(signature), nullptr, nullptr, false, nullptr, code, nullptr);
            }
        }
        catch (const char* e)
        {
            return makeResult(nullptr, nullptr, nullptr, false, nullptr, SDR_OK, (char*)e);
        }
    default:
        return makeResult(nullptr, nullptr, nullptr, false, nullptr, SDR_NOTSUPPORT,
            (char*)"algrithum not support yet");
    }
}
SDFCryptoResult SignWithInternalKey(
    unsigned int keyIndex, char* password, AlgorithmType algorithm, char const* digest)
{
    switch (algorithm)
    {
    case SM2:
        try
        {
            unsigned char* unsignedPwd = reinterpret_cast<unsigned char*>(password);
            std::shared_ptr<const vector<byte>> pwd(
                new const vector<byte>((byte*)unsignedPwd, (byte*)unsignedPwd + 32));
            Key key = Key(keyIndex, pwd);
            SDFCryptoProvider& provider = SDFCryptoProvider::GetInstance();
            std::vector<byte> signature(64);
            unsigned int len;
            unsigned int code = provider.Sign(key, algorithm, fromHex((char*)digest).data(),
                getHexByteLen((char*)digest), signature.data(), &len);
            if (code != SDR_OK)
            {
                return makeResult(nullptr, nullptr, nullptr, false, nullptr, code, nullptr);
            }
            else
            {
                return makeResult(
                    toHex(signature), nullptr, nullptr, false, nullptr, code, nullptr);
            }
        }
        catch (const char* e)
        {
            return makeResult(nullptr, nullptr, nullptr, false, nullptr, SDR_OK, (char*)e);
        }
    default:
        return makeResult(nullptr, nullptr, nullptr, false, nullptr, SDR_NOTSUPPORT,
            (char*)"algrithum not support yet");
    }
}
SDFCryptoResult Verify(
    char* publicKey, AlgorithmType algorithm, char const* digest, char const* signature)
{
    switch (algorithm)
    {
    case SM2:
        try
        {
            Key key = Key();
            std::vector<byte> pk = fromHex((char*)publicKey);
            std::shared_ptr<const vector<byte>> pubKey =
                std::make_shared<const std::vector<byte>>((byte*)pk.data(), (byte*)pk.data() + 64);
            key.setPublicKey(pubKey);
            // SearchData(fromHex(publicKey).data(), 64, 16);
            // SearchData(fromHex((char*)signature).data(), 64, 16);
            // SearchData(fromHex((char*)digest).data(), 32, 16);
            SDFCryptoProvider& provider = SDFCryptoProvider::GetInstance();
            bool isValid;
            unsigned int code = provider.Verify(key, algorithm, fromHex((char*)digest).data(),
                getHexByteLen((char*)digest), fromHex((char*)signature).data(),
                getHexByteLen((char*)signature), &isValid);
            return makeResult(nullptr, nullptr, nullptr, isValid, nullptr, code, nullptr);
        }
        catch (const char* e)
        {
            return makeResult(nullptr, nullptr, nullptr, false, nullptr, SDR_OK, (char*)e);
        }
    default:
        return makeResult(nullptr, nullptr, nullptr, false, nullptr, SDR_NOTSUPPORT,
            (char*)"algrithum not support yet");
    }
}

SDFCryptoResult VerifyWithInternalKey(
    unsigned int keyIndex, AlgorithmType algorithm, char const* digest, char const* signature)
{
    switch (algorithm)
    {
    case SM2:
        try
        {
            Key key = Key(keyIndex);
            // SearchData(fromHex((char *)signature).data(), 64, 16);
            // SearchData(fromHex((char *)digest).data(), 32, 16);
            SDFCryptoProvider& provider = SDFCryptoProvider::GetInstance();
            bool isValid;
            unsigned int code = provider.Verify(key, algorithm, fromHex((char*)digest).data(),
                getHexByteLen((char*)digest), fromHex((char*)signature).data(),
                getHexByteLen((char*)signature), &isValid);
            return makeResult(nullptr, nullptr, nullptr, isValid, nullptr, code, nullptr);
        }
        catch (const char* e)
        {
            return makeResult(nullptr, nullptr, nullptr, false, nullptr, SDR_OK, (char*)e);
        }
    default:
        return makeResult(nullptr, nullptr, nullptr, false, nullptr, SDR_NOTSUPPORT,
            (char*)"algrithum not support yet");
    }
}

SDFCryptoResult Hash(char* publicKey, AlgorithmType algorithm, char const* message)
{
    switch (algorithm)
    {
    case SM3:
        try
        {
            SDFCryptoProvider& provider = SDFCryptoProvider::GetInstance();
            bool isValid;
            // unsigned char hashResult[32];
            vector<byte> hashResult(32);
            unsigned int len;
            unsigned int code = provider.Hash(nullptr, algorithm, fromHex((char*)message).data(),
                getHexByteLen((char*)message), hashResult.data(), &len);
            return makeResult(nullptr, nullptr, nullptr, false, toHex(hashResult), code, nullptr);
        }
        catch (const char* e)
        {
            return makeResult(nullptr, nullptr, nullptr, false, nullptr, SDR_OK, (char*)e);
        }
    default:
        return makeResult(nullptr, nullptr, nullptr, false, nullptr, SDR_NOTSUPPORT,
            (char*)"algrithum not support yet");
    }
}

SDFCryptoResult HashWithZ(char* key, AlgorithmType algorithm, char const* message)
{
    switch (algorithm)
    {
    case SM3:
        try
        {
            SDFCryptoProvider& provider = SDFCryptoProvider::GetInstance();
            bool isValid;
            // unsigned char hashResult[32];
            vector<byte> hashResult(32);
            unsigned int len;
            unsigned int code = provider.Hash(nullptr, algorithm, fromHex((char*)message).data(),
                getHexByteLen((char*)message), hashResult.data(), &len);
            return makeResult(nullptr, nullptr, nullptr, false, toHex(hashResult), code, nullptr);
        }
        catch (const char* e)
        {
            return makeResult(nullptr, nullptr, nullptr, false, nullptr, SDR_OK, (char*)e);
        }
    default:
        return makeResult(nullptr, nullptr, nullptr, false, nullptr, SDR_NOTSUPPORT,
            (char*)"algrithum not support yet");
    }
}

SDFCryptoResult ExportInternalPublicKey(unsigned int keyIndex, AlgorithmType algorithm)
{
    switch (algorithm)
    {
    case SM2:
        try
        {
            SDFCryptoProvider& provider = SDFCryptoProvider::GetInstance();
            Key key = Key(keyIndex);
            unsigned int code = provider.ExportInternalPublicKey(key, SM2);
            if (code == SDR_OK)
            {
                return makeResult(
                    nullptr, toHex(*key.publicKey().get()), nullptr, false, nullptr, code, nullptr);
            }
            else
            {
                return makeResult(nullptr, nullptr, nullptr, false, nullptr, code, nullptr);
            }
        }
        catch (const char* e)
        {
            return makeResult(nullptr, nullptr, nullptr, false, nullptr, SDR_OK, (char*)e);
        }
    default:
        return makeResult(nullptr, nullptr, nullptr, false, nullptr, SDR_NOTSUPPORT,
            (char*)"algrithum not support yet");
    }
}

SDFCryptoResult makeResult(char* signature, char* publicKey, char* privateKey, bool result,
    char* hash, unsigned int code, char* msg)
{
    SDFCryptoResult cryptoResult;
    cryptoResult.signature = signature;
    cryptoResult.publicKey = publicKey;
    cryptoResult.privateKey = privateKey;
    cryptoResult.result = result;
    cryptoResult.hash = hash;
    if (code != SDR_OK)
    {
        cryptoResult.sdfErrorMessage = SDFCryptoProvider::GetInstance().GetErrorMessage(code);
    }
    else
    {
        cryptoResult.sdfErrorMessage = nullptr;
    }
    if (msg != nullptr)
    {
        cryptoResult.sdfErrorMessage = msg;
    }
    return cryptoResult;
}
char* toHex(const std::vector<byte>& data)
{
    static char const* hexdigits = "0123456789abcdef";
    std::string hex(data.size() * 2, '0');
    int position = 0;
    for (int i = 0; i < data.size(); i++)
    {
        hex[position++] = hexdigits[(data[i] >> 4) & 0x0f];
        hex[position++] = hexdigits[data[i] & 0x0f];
    }
    char* c_hex = new char[data.size() * 2 + 1];
    strcpy(c_hex, hex.c_str());
    return c_hex;
}

std::vector<byte> fromHex(char* hexString)
{
    size_t len = strlen(hexString);
    unsigned s = (len >= 2 && hexString[0] == '0' && hexString[1] == 'x') ? 2 : 0;
    std::vector<byte> ret;
    ret.reserve((len - s + 1) / 2);
    if (len % 2)
    {
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

        if (h != -1 && l != -1)
        {
            ret.push_back((uint8_t)(h * 16 + l));
        }
        else
        {
            throw "bad hex string";
        }
    }
    return ret;
}

unsigned int getHexByteLen(char* hexString)
{
    size_t len = strlen(hexString);
    unsigned s = (len >= 2 && hexString[0] == '0' && hexString[1] == 'x') ? 2 : 0;
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

int PrintData(
    char* itemName, unsigned char* sourceData, unsigned int dataLength, unsigned int rowCount)
{
    int i, j;

    if ((sourceData == NULL) || (rowCount == 0) || (dataLength == 0))
        return -1;

    if (itemName != NULL)
        printf("%s[%d]:\n", itemName, dataLength);

    for (i = 0; i < (int)(dataLength / rowCount); i++)
    {
        printf("%08x  ", i * rowCount);

        for (j = 0; j < (int)rowCount; j++)
        {
            printf("%02x ", *(sourceData + i * rowCount + j));
        }

        printf("\n");
    }

    if (!(dataLength % rowCount))
        return 0;

    printf("%08x  ", (dataLength / rowCount) * rowCount);

    for (j = 0; j < (int)(dataLength % rowCount); j++)
    {
        printf("%02x ", *(sourceData + (dataLength / rowCount) * rowCount + j));
    }

    printf("\n");

    return 0;
}

}  // namespace sdf
}  // namespace hsm
