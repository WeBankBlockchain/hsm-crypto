/*
    This file is part of FISCO-BCOS.

    FISCO-BCOS is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    FISCO-BCOS is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with FISCO-BCOS.  If not, see <http://www.gnu.org/licenses/>.
*/
/** @file SDFCryptoProvider.h
 * @author maggiewu
 * @date 2021-02-01
 */
#pragma once
#include "Common.h"
#include "CryptoProvider.h"
#include "gmt0018.h"
#include <stdio.h>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <list>
#include <string>
#include <vector>
using namespace hsm;
namespace hsm
{
class SDFApiWrapper
{
public:
    using Ptr = std::shared_ptr<SDFApiWrapper>;
    SDFApiWrapper(const std::string& libPath);
    virtual ~SDFApiWrapper() {}

    int OpenSession(void* _deviceHandle, void* _sessionHandle)
    {
        return m_openSession(_deviceHandle, _sessionHandle);
    }
    int CloseSession(void* _session) { return m_closeSession(_session); }
    int OpenDevice(void* _deviceHandle) { return m_openDevice(_deviceHandle); }
    int CloseDevice(void* _deviceHandle) { return m_closeDevice(_deviceHandle); }

    int GetPrivateKeyAccessRight(void* _sessionHandle, unsigned int _keyIndex,
        unsigned char* _password, unsigned int _pwdLength)
    {
        return m_getPrivateKeyAccessRight(_sessionHandle, _keyIndex, _password, _pwdLength);
    }
    int ReleasePrivateKeyAccessRight(void* _sessionHandle, unsigned int _keyIndex)
    {
        return m_releasePrivateKeyAccessRight(_sessionHandle, _keyIndex);
    }

    int GenerateKeyPairECC(void* _sessionHandle, unsigned int _algID, unsigned int _keyBits,
        ECCrefPublicKey* _publicKey, ECCrefPrivateKey* _privateKey)
    {
        return m_generateKeyPairECC(_sessionHandle, _algID, _keyBits, _publicKey, _privateKey);
    }
    int InternalSignECC(void* _sessionHandle, unsigned int _keyIndex, unsigned char* _data,
        unsigned int _dataLength, ECCSignature* _signature)
    {
        return m_internalSignECC(_sessionHandle, _keyIndex, _data, _dataLength, _signature);
    }
    int ExternalSignECC(void* _sessionHandle, unsigned int _algID, ECCrefPrivateKey* _privateKey,
        unsigned char* _data, unsigned int _dataLength, ECCSignature* _signature)
    {
        return m_externalSignECC(
            _sessionHandle, _algID, _privateKey, _data, _dataLength, _signature);
    }
    int InternalVerifyECC(void* _sessionHandle, unsigned int _keyIndex, unsigned char* _data,
        unsigned int _dataLength, ECCSignature* _signature)
    {
        return m_internalVerifyECC(_sessionHandle, _keyIndex, _data, _dataLength, _signature);
    }
    int ExternalVerifyECC(void* _sessionHandle, unsigned int _algID, ECCrefPublicKey* _publicKey,
        unsigned char* _dataInput, unsigned int _inputLength, ECCSignature* _signature)
    {
        return m_externalVerifyECC(
            _sessionHandle, _algID, _publicKey, _dataInput, _inputLength, _signature);
    }
    int ExportSignPublicKeyECC(
        void* _sessionHandle, unsigned int _keyIndex, ECCrefPublicKey* _publicKey)
    {
        return m_exportSignPublicKeyECC(_sessionHandle, _keyIndex, _publicKey);
    }

    int HashInit(void* _sessionHandle, unsigned int _algID, ECCrefPublicKey* _publicKey,
        unsigned char* _id, unsigned int _idLength)
    {
        return m_hashInit(_sessionHandle, _algID, _publicKey, _id, _idLength);
    }
    int HashUpdate(void* _sessionHandle, unsigned char* _data, unsigned int _dataLength)
    {
        return m_hashUpdate(_sessionHandle, _data, _dataLength);
    }
    int HashFinal(void* _sessionHandle, unsigned char* _hash, unsigned int* _hashLength)
    {
        return m_hashFinal(_sessionHandle, _hash, _hashLength);
    }

    int ImportKey(
        void* _sessionHandle, unsigned char* _key, unsigned int _keyLength, void** _keyHandle)
    {
        return m_importKey(_sessionHandle, _key, _keyLength, _keyHandle);
    }

    int GetSymmKeyHandle(
        void* _sessionHandle, unsigned int _keyIndex, void** _keyHandle)
    {
        return m_getSymmKeyHandle(_sessionHandle, _keyIndex, _keyHandle);
    }

    int DestroyKey(void* _sessionHandle, void* _keyHandle)
    {
        return m_destroyKey(_sessionHandle, _keyHandle);
    }

    int Encrypt(void* _sessionHandle, void* _keyHandle, unsigned int _algId, unsigned char* _iv,
        unsigned char* _data, unsigned int _dataLength, unsigned char* _encData,
        unsigned int* _encDtaLength)
    {
        return m_encrypt(
            _sessionHandle, _keyHandle, _algId, _iv, _data, _dataLength, _encData, _encDtaLength);
    }
    int Decrypt(void* _sessionHandle, void* _keyHandle, unsigned int _algId, unsigned char* _iv,
        unsigned char* _encData, unsigned int _encDataLength, unsigned char* _data,
        unsigned int* _dataLength)
    {
        return m_decrypt(
            _sessionHandle, _keyHandle, _algId, _iv, _encData, _encDataLength, _data, _dataLength);
    }

    int GenerateRandom(void* _sessionHandle, unsigned int _length, unsigned char* _random)
    {
        return m_generateRandom(_sessionHandle, _length, _random);
    }


private:
#if defined(_WIN32) || defined(__WIN32__) || defined(WIN32)
    HMODULE m_handle;
#else
    void* m_handle;
#endif

    int (*m_openSession)(void*, void*);
    int (*m_closeSession)(void*);
    int (*m_openDevice)(void*);
    int (*m_closeDevice)(void*);

    int (*m_getPrivateKeyAccessRight)(void*, unsigned int, unsigned char*, unsigned int);
    int (*m_releasePrivateKeyAccessRight)(void*, unsigned int);

    int (*m_generateKeyPairECC)(
        void*, unsigned int, unsigned int, ECCrefPublicKey*, ECCrefPrivateKey*);
    int (*m_internalSignECC)(void*, unsigned int, unsigned char*, unsigned int, ECCSignature*);
    int (*m_externalSignECC)(
        void*, unsigned int, ECCrefPrivateKey*, unsigned char*, unsigned int, ECCSignature*);
    int (*m_internalVerifyECC)(void*, unsigned int, unsigned char*, unsigned int, ECCSignature*);
    int (*m_externalVerifyECC)(
        void*, unsigned int, ECCrefPublicKey*, unsigned char*, unsigned int, ECCSignature*);
    int (*m_exportSignPublicKeyECC)(void*, unsigned int, ECCrefPublicKey*);

    int (*m_hashInit)(void*, unsigned int, ECCrefPublicKey*, unsigned char*, unsigned int);
    int (*m_hashUpdate)(void*, unsigned char*, unsigned int);
    int (*m_hashFinal)(void*, unsigned char*, unsigned int*);

    int (*m_importKey)(void*, unsigned char*, unsigned int, void**);
    int (*m_getSymmKeyHandle)(void*, unsigned int, void**);
    int (*m_destroyKey)(void*, void*);

    int (*m_encrypt)(void*, void*, unsigned int, unsigned char*, unsigned char*, unsigned int,
        unsigned char*, unsigned int*);
    int (*m_decrypt)(void*, void*, unsigned int, unsigned char*, unsigned char*, unsigned int,
        unsigned char*, unsigned int*);

    int (*m_generateRandom)(void*, unsigned int, unsigned char*);
};

class SessionPool
{
public:
    using Ptr = std::shared_ptr<SessionPool>;
    SessionPool(int _size, void* _deviceHandle, SDFApiWrapper::Ptr _sdfApiWrapper);
    void* GetSession();
    void ReturnSession(void* session);

private:
    void* m_deviceHandle;
    size_t m_size;
    size_t m_available_session_count;
    SDFApiWrapper::Ptr m_SDFApiWrapper;
    std::mutex mtx;
    std::condition_variable cv;
};

/**
 *  SDFCryptoProvider suply SDF function calls
 *  Singleton
 */
class SDFCryptoProvider : public CryptoProvider
{
public:
    SDFCryptoProvider(const std::string& libPath);
    SDFCryptoProvider(int sessionPoolSize, const std::string& libPath);
    ~SDFCryptoProvider();
    SDFCryptoProvider(const SDFCryptoProvider&) = default;
    SDFCryptoProvider& operator=(const SDFCryptoProvider&) = default;

public:
    /**
     * Return the instance
     */
    static SDFCryptoProvider& GetInstance(
        const std::string& libPath = "/usr/local/lib/libgmt0018.so");
    static SDFCryptoProvider& GetInstance(
        int sessionPoolSize, const std::string& libPath = "/usr/local/lib/libgmt0018.so");

    /**
     * Generate key
     * Return error code
     */
    unsigned int KeyGen(AlgorithmType algorithm, Key* key) override;

    /**
     * Sign
     */
    unsigned int Sign(Key const& key, AlgorithmType algorithm, unsigned char const* digest,
        unsigned int digestLen, unsigned char* signature, unsigned int* signatureLen) override;

    /**
     * Verify signature
     */
    unsigned int Verify(Key const& key, AlgorithmType algorithm, unsigned char const* digest,
        unsigned int digestLen, unsigned char const* signature, unsigned int signatureLen,
        bool* result) override;

    /**
     * Make hash
     */
    unsigned int Hash(Key* key, AlgorithmType algorithm, unsigned char const* message,
        unsigned int messageLen, unsigned char* digest, unsigned int* digestLen) override;

    /**
     * Encrypt
     */
    unsigned int Encrypt(Key const& key, AlgorithmType algorithm, unsigned char* iv,
        unsigned char const* plantext, unsigned int plantextLen, unsigned char* cyphertext,
        unsigned int* cyphertextLen) override;

    unsigned int EncryptWithInternalKey(unsigned int keyIndex, AlgorithmType algorithm, unsigned char* iv,
        unsigned char const* plantext, unsigned int plantextLen, unsigned char* cyphertext,
        unsigned int* cyphertextLen);

    /**
     * Decrypt
     */
    unsigned int Decrypt(Key const& key, AlgorithmType algorithm, unsigned char* iv,
        unsigned char const* cyphertext, unsigned int cyphertextLen, unsigned char* plantext,
        unsigned int* plantextLen) override;

    unsigned int DecryptWithInternalKey(unsigned int keyIndex, AlgorithmType algorithm, unsigned char* iv,
        unsigned char const* cyphertext, unsigned int cyphertextLen, unsigned char* plantext,
        unsigned int* plantextLen);

    /**
     *  Get public key of an internal key
     */
    unsigned int ExportInternalPublicKey(Key& key, AlgorithmType algorithm) override;

    /**
     *  generate random number
     */
    bool GenerateRandom(unsigned int randomLength, unsigned char* pucRandom);

    SDFApiWrapper::Ptr GetSDFApiWrapper() { return m_SDFApiWrapper; }

    char* GetErrorMessage(unsigned int code) override;
    static const unsigned int SM2_BITS;
    static const std::string SM2_USER_ID;

private:
    void* m_deviceHandle;
    SessionPool::Ptr m_sessionPool;
    std::string m_libPath;
    SDFApiWrapper::Ptr m_SDFApiWrapper;
};

struct SDFCryptoResult
{
    char* signature;
    char* publicKey;
    char* privateKey;
    bool result;
    char* hash;
    char* sdfErrorMessage;
};

SDFCryptoResult KeyGen(const std::string& libPath, AlgorithmType algorithm);
SDFCryptoResult Sign(
    const std::string& libPath, char* privateKey, AlgorithmType algorithm, char const* digest);
SDFCryptoResult SignWithInternalKey(const std::string& libPath, unsigned int keyIndex,
    char* password, AlgorithmType algorithm, char const* digest);
SDFCryptoResult Verify(const std::string& libPath, char* publicKey, AlgorithmType algorithm,
    char const* digest, char const* signature);
SDFCryptoResult VerifyWithInternalKey(const std::string& libPath, unsigned int keyIndex,
    AlgorithmType algorithm, char const* digest, char const* signature);
SDFCryptoResult Hash(
    const std::string& libPath, char* key, AlgorithmType algorithm, char const* message);
SDFCryptoResult ExportInternalPublicKey(
    const std::string& libPath, unsigned int keyIndex, AlgorithmType algorithm);
SDFCryptoResult makeResult(char* signature, char* publicKey, char* privateKey, bool result,
    char* hash, unsigned int code, char*);
char* sdfToHex(const std::vector<byte>& data);
std::vector<byte> sdfFromHex(char* hexString);
int fromHexChar(char _i);
unsigned int getHexByteLen(char* hexString);
int PrintData(char*, unsigned char*, unsigned int, unsigned int);
std::string getSdfErrorMessage(unsigned int code);
}  // namespace hsm
