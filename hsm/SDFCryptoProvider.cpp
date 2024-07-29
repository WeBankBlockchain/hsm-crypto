#if defined(_WIN32) || defined(__WIN32__) || defined(WIN32)
#define dlopen(path, arg2) LoadLibrary(path)
#define dlsym(handle, func) GetProcAddress(handle, func)
#define dlerror() GetLastError()
#define dlclose(args) FreeLibrary(args)
#else
#include <dlfcn.h>
#endif

#include "Common.h"
#include "SDFCryptoProvider.h"
#include <stdio.h>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <iostream>
#include <list>
#include <memory>
#include <string>
#include <vector>
using namespace hsm;

namespace hsm
{

SDFApiWrapper::SDFApiWrapper(const std::string& libPath)
{
    m_handle = dlopen(libPath.c_str(), RTLD_LAZY);

    char* errstr;
#if defined(_WIN32) || defined(__WIN32__) || defined(WIN32)
    errstr = reinterpret_cast<char*>(dlerror());
#else
    errstr = dlerror();
#endif
    if (errstr != NULL)
    {
        throw std::runtime_error("A dynamic linking error occurred: " + std::string(errstr) +
                                 " , Cannot dynamic loading SDF lib, lib path: " + libPath);
    }

    if (!m_handle)
    {
        throw std::runtime_error("Cannot dynamic loading SDF lib, lib path: " + libPath);
    }

    m_openSession = (int (*)(void*, void*))dlsym(m_handle, "SDF_OpenSession");
    m_closeSession = (int (*)(void*))dlsym(m_handle, "SDF_CloseSession");
    m_openDevice = (int (*)(void*))dlsym(m_handle, "SDF_OpenDevice");
    m_closeDevice = (int (*)(void*))dlsym(m_handle, "SDF_CloseDevice");

    m_getPrivateKeyAccessRight = (int (*)(void*, unsigned int, unsigned char*, unsigned int))dlsym(
        m_handle, "SDF_GetPrivateKeyAccessRight");
    m_releasePrivateKeyAccessRight =
        (int (*)(void*, unsigned int))dlsym(m_handle, "SDF_ReleasePrivateKeyAccessRight");

    m_generateKeyPairECC = (int (*)(void*, unsigned int, unsigned int, ECCrefPublicKey*,
        ECCrefPrivateKey*))dlsym(m_handle, "SDF_GenerateKeyPair_ECC");
    m_internalSignECC = (int (*)(void*, unsigned int, unsigned char*, unsigned int,
        ECCSignature*))dlsym(m_handle, "SDF_InternalSign_ECC");
    m_externalSignECC = (int (*)(void*, unsigned int, ECCrefPrivateKey*, unsigned char*,
        unsigned int, ECCSignature*))dlsym(m_handle, "SDF_ExternalSign_ECC");
    m_internalVerifyECC = (int (*)(void*, unsigned int, unsigned char*, unsigned int,
        ECCSignature*))dlsym(m_handle, "SDF_InternalVerify_ECC");
    m_externalVerifyECC = (int (*)(void*, unsigned int, ECCrefPublicKey*, unsigned char*,
        unsigned int, ECCSignature*))dlsym(m_handle, "SDF_ExternalVerify_ECC");
    m_exportSignPublicKeyECC = (int (*)(void*, unsigned int, ECCrefPublicKey*))dlsym(
        m_handle, "SDF_ExportSignPublicKey_ECC");

    m_hashInit = (int (*)(void*, unsigned int, ECCrefPublicKey*, unsigned char*,
        unsigned int))dlsym(m_handle, "SDF_HashInit");
    m_hashUpdate = (int (*)(void*, unsigned char*, unsigned int))dlsym(m_handle, "SDF_HashUpdate");
    m_hashFinal = (int (*)(void*, unsigned char*, unsigned int*))dlsym(m_handle, "SDF_HashFinal");

    m_importKey =
        (int (*)(void*, unsigned char*, unsigned int, void**))dlsym(m_handle, "SDF_ImportKey");
    m_getSymmKeyHandle =
        (int (*)(void*, unsigned int, void**))dlsym(m_handle, "SDF_GetSymmKeyHandle");
    m_destroyKey = (int (*)(void*, void*))dlsym(m_handle, "SDF_DestroyKey");

    m_encrypt = (int (*)(void*, void*, unsigned int, unsigned char*, unsigned char*, unsigned int,
        unsigned char*, unsigned int*))dlsym(m_handle, "SDF_Encrypt");
    m_decrypt = (int (*)(void*, void*, unsigned int, unsigned char*, unsigned char*, unsigned int,
        unsigned char*, unsigned int*))dlsym(m_handle, "SDF_Decrypt");

    m_generateRandom =
        (int (*)(void*, unsigned int, unsigned char*))dlsym(m_handle, "SDF_GenerateRandom");
}

    SDFApiWrapper::~SDFApiWrapper() {
        if (m_handle) {
            dlclose(m_handle);
            m_handle = NULL;
        }
    }

    const unsigned int SDFCryptoProvider::SM2_BITS = 256;
    const std::string SDFCryptoProvider::SM2_USER_ID = "1234567812345678";

    SDFCryptoProvider::SDFCryptoProvider(const std::string &libPath) {
        m_libPath = libPath;
        m_SDFApiWrapper = std::make_shared<SDFApiWrapper>(m_libPath);
        SGD_RV deviceStatus = m_SDFApiWrapper->OpenDevice(&m_deviceHandle);
        if (deviceStatus != SDR_OK) {
        throw std::runtime_error("Cannot open device, error: " + getSdfErrorMessage(deviceStatus));
    }
    m_sessionPool = std::make_shared<SessionPool>(50, m_deviceHandle, m_SDFApiWrapper);
}

SDFCryptoProvider::SDFCryptoProvider(int sessionPoolSize, const std::string& libPath)
{
    m_libPath = libPath;
    m_SDFApiWrapper = std::make_shared<SDFApiWrapper>(m_libPath);
    SGD_RV deviceStatus = m_SDFApiWrapper->OpenDevice(&m_deviceHandle);
    if (deviceStatus != SDR_OK)
    {
        throw std::runtime_error("Cannot open device, error: " + getSdfErrorMessage(deviceStatus));
    }
    m_sessionPool = std::make_shared<SessionPool>(sessionPoolSize, m_deviceHandle, m_SDFApiWrapper);
}

SDFCryptoProvider::~SDFCryptoProvider()
{
    if (m_deviceHandle != NULL)
    {
        m_SDFApiWrapper->CloseDevice(m_deviceHandle);
    }
}

SDFCryptoProvider& SDFCryptoProvider::GetInstance(const std::string& libPath)
{
    return GetInstance(10, libPath);
}

SDFCryptoProvider& SDFCryptoProvider::GetInstance(int sessionPoolSize, const std::string& libPath)
{
    static SDFCryptoProvider instance(sessionPoolSize, libPath);
    return instance;
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
            if (key.password() != NULL && key.password()->size() != 0)
            {
                SGD_RV getAccessRightCode =
                    m_SDFApiWrapper->GetPrivateKeyAccessRight(sessionHandle, key.identifier(),
                        (SGD_UCHAR*)key.password()->data(), (SGD_UINT32)key.password()->size());
                if (getAccessRightCode != SDR_OK)
                {
                    m_sessionPool->ReturnSession(sessionHandle);
                    return getAccessRightCode;
                }
            }
            ECCSignature eccSignature;
            signCode = m_SDFApiWrapper->InternalSignECC(
                sessionHandle, key.identifier(), (SGD_UCHAR*)digest, digestLen, &eccSignature);
            memcpy(signature, eccSignature.r + 32, 32);
            memcpy(signature + 32, eccSignature.s + 32, 32);
            if (key.password() != NULL && key.password()->size() != 0)
            {
                m_SDFApiWrapper->ReleasePrivateKeyAccessRight(sessionHandle, key.identifier());
            }
        }
        else
        {
            ECCrefPrivateKey eccKey;
            eccKey.bits = SM2_BITS;
            memcpy(eccKey.K + 32, key.privateKey()->data(), 32);
            ECCSignature eccSignature;
            signCode = m_SDFApiWrapper->ExternalSignECC(
                sessionHandle, SGD_SM2_1, &eccKey, (SGD_UCHAR*)digest, digestLen, &eccSignature);
            memcpy(signature, eccSignature.r + 32, 32);
            memcpy(signature + 32, eccSignature.s + 32, 32);
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
        ECCrefPublicKey pk = {0};
        ECCrefPrivateKey sk = {0};
        SGD_UINT32 keyLen = SM2_BITS;

        SGD_HANDLE sessionHandle = m_sessionPool->GetSession();
        SGD_RV result =
            m_SDFApiWrapper->GenerateKeyPairECC(sessionHandle, SGD_SM2, keyLen, &pk, &sk);
        if (result != SDR_OK)
        {
            m_sessionPool->ReturnSession(sessionHandle);
            return result;
        }

        std::shared_ptr<const std::vector<byte>> privKey =
            std::make_shared<const std::vector<byte>>((byte*)sk.K + 32, (byte*)sk.K + 64);
        std::shared_ptr<std::vector<byte>> pubKey = std::make_shared<std::vector<byte>>();
        pubKey->reserve(32 + 32);
        pubKey->insert(pubKey->end(), (byte*)pk.x + 32, (byte*)pk.x + 64);
        pubKey->insert(pubKey->end(), (byte *) pk.y + 32, (byte *) pk.y + 64);
        key->setPrivateKey(privKey);
        key->setPublicKey(pubKey);
        m_sessionPool->ReturnSession(sessionHandle);
        return SDR_OK;
    }
        default:
            return SDR_ALGNOTSUPPORT;
    }
}

unsigned int SDFCryptoProvider::Hash(Key *key, AlgorithmType algorithm,
                                     unsigned char const *message, unsigned int messageLen,
                                     unsigned char *digest, unsigned int *digestLen) {
    if (algorithm != SM3) {
        return SDR_ALGNOTSUPPORT;
    }

    SGD_HANDLE sessionHandle = m_sessionPool->GetSession();
    if (sessionHandle == nullptr) {
        return SWR_DEVICE_STATUS_ERR;
    }

    SGD_RV code;
    ECCrefPublicKey eccKey;
    if (key != nullptr) {
        eccKey.bits = SM2_BITS;
        memcpy(eccKey.x + 32, key->publicKey()->data(), 32);
        memcpy(eccKey.y + 32, key->publicKey()->data() + 32, 32);
        code = m_SDFApiWrapper->HashInit(sessionHandle, SGD_SM3, &eccKey, (unsigned char *) SM2_USER_ID.c_str(), 16);
    } else {
        code = m_SDFApiWrapper->HashInit(sessionHandle, SGD_SM3, nullptr, nullptr, 0);
    }

    if (code != SDR_OK) {
        m_sessionPool->ReturnSession(sessionHandle);
        return code; // 返回错误代码
    }

    code = m_SDFApiWrapper->HashUpdate(sessionHandle, (SGD_UCHAR *) message, messageLen);
    if (code != SDR_OK) {
        m_sessionPool->ReturnSession(sessionHandle);
        return code;
    }

    code = m_SDFApiWrapper->HashFinal(sessionHandle, digest, digestLen);
    m_sessionPool->ReturnSession(sessionHandle);

    return code;
}

unsigned int SDFCryptoProvider::Verify(Key const &key, AlgorithmType algorithm,
                                       unsigned char const *digest, unsigned int digestLen,
                                       unsigned char const *signature, const unsigned int signatureLen, bool *result) {
    if (algorithm != SM2) {
        return SDR_NOTSUPPORT;
    }

    if (signatureLen != 64) {
        return SDR_NOTSUPPORT;
    }

    SGD_HANDLE sessionHandle = nullptr;
    sessionHandle = m_sessionPool->GetSession();

    ECCSignature eccSignature;
    memcpy(eccSignature.r + 32, signature, 32);
    memcpy(eccSignature.s + 32, signature + 32, 32);
    SGD_RV code;

    if (key.isInternalKey()) {
        code = m_SDFApiWrapper->InternalVerifyECC(
                sessionHandle, key.identifier(), (SGD_UCHAR *) digest, digestLen, &eccSignature);
    } else {
        ECCrefPublicKey eccKey;
        eccKey.bits = SM2_BITS;
        memcpy(eccKey.x + 32, key.publicKey()->data(), 32);
        memcpy(eccKey.y + 32, key.publicKey()->data() + 32, 32);
        code = m_SDFApiWrapper->ExternalVerifyECC(sessionHandle, SGD_SM2_1, &eccKey, (SGD_UCHAR *) digest, digestLen,
                                                  &eccSignature);
    }

    m_sessionPool->ReturnSession(sessionHandle);
    if (code != SDR_OK) {
        return code;
    }

    *result = (code == SDR_OK);
    return SDR_OK;
}

    unsigned int SDFCryptoProvider::ExportInternalPublicKey(Key &key, AlgorithmType algorithm) {
        switch (algorithm) {
            case SM2: {
                if (!key.isInternalKey()) {
                    return SDR_ALGNOTSUPPORT;
                }
                ECCrefPublicKey pk;
                SGD_HANDLE sessionHandle = m_sessionPool->GetSession();
                SGD_RV result =
                        m_SDFApiWrapper->ExportSignPublicKeyECC(sessionHandle, key.identifier(), &pk);
                if (result != SDR_OK) {
                    m_sessionPool->ReturnSession(sessionHandle);
                    return result;
                }
                std::shared_ptr<std::vector<byte>> pubKey = std::make_shared<std::vector<byte>>();
                pubKey->reserve(32 + 32);
        pubKey->insert(pubKey->end(), (byte*)pk.x + 32, (byte*)pk.x + 64);
        pubKey->insert(pubKey->end(), (byte*)pk.y + 32, (byte*)pk.y + 64);
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
        SGD_HANDLE keyHandler = NULL;
        SGD_RV importResult = m_SDFApiWrapper->ImportKey(sessionHandle,
            (SGD_UCHAR*)key.symmetrickey()->data(), key.symmetrickey()->size(), &keyHandler);
        if (!importResult == SDR_OK)
        {
            m_sessionPool->ReturnSession(sessionHandle);
            return importResult;
        }
        SGD_RV result =
            m_SDFApiWrapper->Encrypt(sessionHandle, keyHandler, SGD_SM4_CBC, (SGD_UCHAR*)iv,
                (SGD_UCHAR*)plantext, plantextLen, (SGD_UCHAR*)cyphertext, cyphertextLen);
        m_SDFApiWrapper->DestroyKey(sessionHandle, keyHandler);
        m_sessionPool->ReturnSession(sessionHandle);
        return result;
    }
    default:
        return SDR_ALGNOTSUPPORT;
    }
}

unsigned int SDFCryptoProvider::EncryptWithInternalKey(unsigned int keyIndex,
    AlgorithmType algorithm, unsigned char* iv, unsigned char const* plantext,
    unsigned int plantextLen, unsigned char* cyphertext, unsigned int* cyphertextLen)
{
    switch (algorithm)
    {
    case SM4_CBC:
    {
        SGD_HANDLE sessionHandle = m_sessionPool->GetSession();
        SGD_HANDLE keyHandler = NULL;
        SGD_RV getSymmKeyResult =
            m_SDFApiWrapper->GetSymmKeyHandle(sessionHandle, keyIndex, &keyHandler);

        if (!getSymmKeyResult == SDR_OK)
        {
            m_sessionPool->ReturnSession(sessionHandle);
            return getSymmKeyResult;
        }

        SGD_RV result =
            m_SDFApiWrapper->Encrypt(sessionHandle, keyHandler, SGD_SM4_CBC, (SGD_UCHAR*)iv,
                (SGD_UCHAR*)plantext, plantextLen, (SGD_UCHAR*)cyphertext, cyphertextLen);
        m_SDFApiWrapper->DestroyKey(sessionHandle, keyHandler);
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
        SGD_HANDLE keyHandler = NULL;
        SGD_RV importResult = m_SDFApiWrapper->ImportKey(sessionHandle,
            (SGD_UCHAR*)key.symmetrickey()->data(), key.symmetrickey()->size(), &keyHandler);
        if (!importResult == SDR_OK)
        {
            m_sessionPool->ReturnSession(sessionHandle);
            return importResult;
        }
        SGD_RV result =
            m_SDFApiWrapper->Decrypt(sessionHandle, keyHandler, SGD_SM4_CBC, (SGD_UCHAR*)iv,
                (SGD_UCHAR*)cyphertext, cyphertextLen, (SGD_UCHAR*)plantext, plantextLen);
        m_SDFApiWrapper->DestroyKey(sessionHandle, keyHandler);
        m_sessionPool->ReturnSession(sessionHandle);
        return result;
    }
    default:
        return SDR_ALGNOTSUPPORT;
    }
}

unsigned int SDFCryptoProvider::DecryptWithInternalKey(unsigned int keyIndex,
    AlgorithmType algorithm, unsigned char* iv, unsigned char const* cyphertext,
    unsigned int cyphertextLen, unsigned char* plantext, unsigned int* plantextLen)
{
    switch (algorithm)
    {
    case SM4_CBC:
    {
        SGD_HANDLE sessionHandle = m_sessionPool->GetSession();
        SGD_HANDLE keyHandler = NULL;
        SGD_RV getSymmKeyResult =
            m_SDFApiWrapper->GetSymmKeyHandle(sessionHandle, keyIndex, &keyHandler);
        if (!getSymmKeyResult == SDR_OK)
        {
            m_sessionPool->ReturnSession(sessionHandle);
            return getSymmKeyResult;
        }
        SGD_RV result =
            m_SDFApiWrapper->Decrypt(sessionHandle, keyHandler, SGD_SM4_CBC, (SGD_UCHAR*)iv,
                (SGD_UCHAR*)cyphertext, cyphertextLen, (SGD_UCHAR*)plantext, plantextLen);
        m_SDFApiWrapper->DestroyKey(sessionHandle, keyHandler);
        m_sessionPool->ReturnSession(sessionHandle);
        return result;
    }
    default:
        return SDR_ALGNOTSUPPORT;
    }
}

char* SDFCryptoProvider::GetErrorMessage(unsigned int code)
{
    std::string errorMessage = getSdfErrorMessage(code);
    return (char*)errorMessage.c_str();
}

SDFCryptoResult KeyGen(const std::string& libPath, AlgorithmType algorithm)
{
    switch (algorithm)
    {
    case SM2:
        try
        {
            SDFCryptoProvider& provider = SDFCryptoProvider::GetInstance(libPath);
            Key key = Key();
            unsigned int code = provider.KeyGen(algorithm, &key);
            if (code != SDR_OK)
            {
                return makeResult(nullptr, nullptr, nullptr, false, nullptr, code, nullptr);
            }
            else
            {
                return makeResult(nullptr, sdfToHex(*key.publicKey().get()),
                    sdfToHex(*key.privateKey().get()), false, nullptr, code, nullptr);
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

SDFCryptoResult Sign(
    const std::string& libPath, char* privateKey, AlgorithmType algorithm, char const* digest)
{
    switch (algorithm)
    {
    case SM2:
        try
        {
            if (privateKey == nullptr || digest == nullptr)
            {
                return makeResult(nullptr, nullptr, nullptr, false, nullptr, SDR_NOTSUPPORT,
                    (char*)"private key and digest can not be null. Please check your parameters.");
            }
            Key key = Key();
            const std::vector<byte> sk = sdfFromHex(privateKey);
            std::shared_ptr<const std::vector<byte>> privKey =
                std::make_shared<const std::vector<byte>>((byte*)sk.data(), (byte*)sk.data() + 32);
            key.setPrivateKey(privKey);
            SDFCryptoProvider& provider = SDFCryptoProvider::GetInstance(libPath);
            std::vector<byte> signature(64);
            // unsigned char* signature = (unsigned char*)malloc(64 * sizeof(char));
            unsigned int len;
            unsigned int code = provider.Sign(key, algorithm, sdfFromHex((char*)digest).data(),
                getHexByteLen((char*)digest), signature.data(), &len);
            if (code != SDR_OK)
            {
                return makeResult(nullptr, nullptr, nullptr, false, nullptr, code, nullptr);
            }
            else
            {
                return makeResult(
                    sdfToHex(signature), nullptr, nullptr, false, nullptr, code, nullptr);
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
SDFCryptoResult SignWithInternalKey(const std::string& libPath, unsigned int keyIndex,
    char* password, AlgorithmType algorithm, char const* digest)
{
    switch (algorithm)
    {
    case SM2:
        try
        {
            if (keyIndex < 1)
            {
                return makeResult(nullptr, nullptr, nullptr, false, nullptr, SDR_NOTSUPPORT,
                    (char*)"keyIndex should be larger than 1. Please check your parameters.");
            }
            unsigned char* unsignedPwd = reinterpret_cast<unsigned char*>(password);
            std::shared_ptr<const std::vector<byte>> pwd(new const std::vector<byte>(
                (byte*)unsignedPwd, (byte*)unsignedPwd + strlen(password)));
            Key key = Key(keyIndex, pwd);
            SDFCryptoProvider& provider = SDFCryptoProvider::GetInstance(libPath);
            std::vector<byte> signature(64);
            unsigned int len;
            unsigned int code = provider.Sign(key, algorithm, sdfFromHex((char*)digest).data(),
                getHexByteLen((char*)digest), signature.data(), &len);
            if (code != SDR_OK)
            {
                return makeResult(nullptr, nullptr, nullptr, false, nullptr, code, nullptr);
            }
            else
            {
                return makeResult(
                    sdfToHex(signature), nullptr, nullptr, false, nullptr, code, nullptr);
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
SDFCryptoResult Verify(const std::string& libPath, char* publicKey, AlgorithmType algorithm,
    char const* digest, char const* signature)
{
    switch (algorithm)
    {
    case SM2:
        try
        {
            if (publicKey == nullptr || digest == nullptr || signature == nullptr)
            {
                return makeResult(nullptr, nullptr, nullptr, false, nullptr, SDR_NOTSUPPORT,
            (char*)"prublicKey, digest, signature can not be null. Please check your parameters.");
            }
            Key key = Key();
            std::vector<byte> pk = sdfFromHex((char*)publicKey);
            std::shared_ptr<const std::vector<byte>> pubKey =
                std::make_shared<const std::vector<byte>>((byte*)pk.data(), (byte*)pk.data() + 64);
            key.setPublicKey(pubKey);
            SDFCryptoProvider& provider = SDFCryptoProvider::GetInstance(libPath);
            bool isValid;
            unsigned int code = provider.Verify(key, algorithm, sdfFromHex((char*)digest).data(),
                getHexByteLen((char*)digest), sdfFromHex((char*)signature).data(),
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

SDFCryptoResult VerifyWithInternalKey(const std::string& libPath, unsigned int keyIndex,
    AlgorithmType algorithm, char const* digest, char const* signature)
{
    switch (algorithm)
    {
    case SM2:
        try
        {
            Key key = Key(keyIndex);
            SDFCryptoProvider& provider = SDFCryptoProvider::GetInstance(libPath);
            bool isValid;
            unsigned int code = provider.Verify(key, algorithm, sdfFromHex((char*)digest).data(),
                getHexByteLen((char*)digest), sdfFromHex((char*)signature).data(),
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

SDFCryptoResult Hash(
    const std::string& libPath, char* publicKey, AlgorithmType algorithm, char const* message)
{
    switch (algorithm)
    {
    case SM3:
        try
        {
            SDFCryptoProvider& provider = SDFCryptoProvider::GetInstance(libPath);
            bool isValid;
            std::vector<byte> hashResult(32);
            unsigned int len;
            unsigned int code;
            if (publicKey != nullptr)
            {
                // if publicKey != nullptr, then hash with z value.
                Key key = Key();
                std::vector<byte> pk = sdfFromHex((char*)publicKey);
                std::shared_ptr<const std::vector<byte>> pubKey =
                    std::make_shared<const std::vector<byte>>(
                        (byte*)pk.data(), (byte*)pk.data() + 64);
                key.setPublicKey(pubKey);
                code = provider.Hash(&key, algorithm, sdfFromHex((char*)message).data(),
                    getHexByteLen((char*)message), hashResult.data(), &len);
            }
            else
            {
                code = provider.Hash(nullptr, algorithm, sdfFromHex((char*)message).data(),
                    getHexByteLen((char*)message), hashResult.data(), &len);
            }
            return makeResult(
                nullptr, nullptr, nullptr, false, sdfToHex(hashResult), code, nullptr);
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

SDFCryptoResult ExportInternalPublicKey(
    const std::string& libPath, unsigned int keyIndex, AlgorithmType algorithm)
{
    switch (algorithm)
    {
    case SM2:
        try
        {
            SDFCryptoProvider& provider = SDFCryptoProvider::GetInstance(libPath);
            Key key = Key(keyIndex);
            unsigned int code = provider.ExportInternalPublicKey(key, SM2);
            if (code == SDR_OK)
            {
                return makeResult(nullptr, sdfToHex(*key.publicKey().get()), nullptr, false,
                    nullptr, code, nullptr);
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

bool SDFCryptoProvider::GenerateRandom(unsigned int randomLength, unsigned char* pucRandom)
{
    try
    {
        SDFCryptoProvider& provider = SDFCryptoProvider::GetInstance(m_libPath);
        SGD_HANDLE sessionHandle = m_sessionPool->GetSession();
        SGD_RV result = m_SDFApiWrapper->GenerateRandom(sessionHandle, randomLength, pucRandom);
        m_sessionPool->ReturnSession(sessionHandle);
        if (result == SDR_OK)
        {
            return true;
        }
        return false;
    }
    catch (const char* e)
    {
        return false;
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
        cryptoResult.sdfErrorMessage = (char*)getSdfErrorMessage(code).c_str();
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
char* sdfToHex(const std::vector<byte>& data)
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

std::vector<byte> sdfFromHex(char* hexString)
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
            throw std::runtime_error("bad hex string");
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
            throw std::runtime_error("bad hex string");
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

std::string getSdfErrorMessage(unsigned int code)
{
    switch (code)
    {
    case SDR_OK:
        return "success";
    case SDR_UNKNOWERR:
        return "unknown error";
    case SDR_NOTSUPPORT:
        return "not support";
    case SDR_COMMFAIL:
        return "communication failed";
    case SDR_OPENDEVICE:
        return "failed open device";
    case SDR_OPENSESSION:
        return "failed open session";
    case SDR_PARDENY:
        return "permission deny";
    case SDR_KEYNOTEXIST:
        return "key not exit";
    case SDR_ALGNOTSUPPORT:
        return "algorithm not support";
    case SDR_ALGMODNOTSUPPORT:
        return "algorithm not support mode";
    case SDR_PKOPERR:
        return "public key calculate error";
    case SDR_SKOPERR:
        return "private key calculate error";
    case SDR_SIGNERR:
        return "signature error";
    case SDR_VERIFYERR:
        return "verify signature error";
    case SDR_SYMOPERR:
        return "symmetric crypto calculate error";
    case SDR_STEPERR:
        return "step error";
    case SDR_FILESIZEERR:
        return "file size error";
    case SDR_FILENOEXIST:
        return "file not exist";
    case SDR_FILEOFSERR:
        return "file offset error";
    case SDR_KEYTYPEERR:
        return "key type not right";
    case SDR_KEYERR:
        return "key error";
    default:
        return "unkown code " + std::to_string(code);
    }
}

}  // namespace hsm
