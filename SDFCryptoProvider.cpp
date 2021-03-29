#include "SDFCryptoProvider.h"
#include "libsdf/swsds.h"
#include <cstring>
#include <list>
#include <iostream>

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
    char const* digest, unsigned int const digestLen, char* signature,
    unsigned int* signatureLen)
{
    switch (algorithm)
    {
    case SM2:
    {
        SGD_HANDLE sessionHandle = m_sessionPool->GetSession();
        ECCrefPrivateKey eccKey;
        eccKey.bits = 32 * 8;
        memcpy(eccKey.D, key.PrivateKey(), 32);
        SGD_RV signCode = SDF_ExternalSign_ECC(sessionHandle, SGD_SM2_1, &eccKey,
            (SGD_UCHAR*)digest, digestLen, (ECCSignature*)signature);
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
        std::basic_string<unsigned char> pk_x = pk.x;
        std::basic_string<unsigned char> pk_y = pk.y;
        std::basic_string<unsigned char> pk_xy = pk_x + pk_y;
        key->setPrivateKey((char*)sk.D, sk.bits / 8);
        key->setPublicKey((char*)pk_xy.c_str(), pk.bits / 4);
        m_sessionPool->ReturnSession(sessionHandle);
        return SDR_OK;
    }
    default:
        return SDR_ALGNOTSUPPORT;
    }
}

unsigned int SDFCryptoProvider::Hash(Key*, AlgorithmType algorithm, char const* message,
    unsigned int const messageLen, char* digest, unsigned int* digestLen)
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

        code = SDF_HashFinal(sessionHandle, (SGD_UCHAR*)digest, digestLen);
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
unsigned int SDFCryptoProvider::HashWithZ(Key*, AlgorithmType algorithm, char const* zValue,
    unsigned int const zValueLen, char const* message, unsigned int const messageLen,
    char* digest, unsigned int* digestLen)
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

        code = SDF_HashFinal(sessionHandle, (SGD_UCHAR*)digest, digestLen);
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
    char const* digest, unsigned int const digestLen, char const* signature,
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
        ECCrefPublicKey eccKey;
        eccKey.bits = 32 * 8;
        memcpy(eccKey.x, key.PublicKey(), 32);
        memcpy(eccKey.y, key.PublicKey() + 32, 32);
        ECCSignature eccSignature;
        memcpy(eccSignature.r, signature, 32);
        memcpy(eccSignature.s, signature + 32, 32);
        SGD_RV code = SDF_ExternalVerify_ECC(
            sessionHandle, SGD_SM2_1, &eccKey, (SGD_UCHAR*)digest, digestLen, &eccSignature);
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

char * SDFCryptoProvider::GetErrorMessage(unsigned int code)
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
        string err = "unkown code " + std::to_string(code);
        return (char *)err.c_str();
    }
}

}  // namespace crypto
}  // namespace dev
