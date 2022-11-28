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
#include "../Common.h"
#include "../CryptoProvider.h"
#include <stdio.h>
#include <cstdlib>
#include <cstring>
#include <list>
#include <string>
#include <vector>
#include<condition_variable>
using namespace hsm;
namespace hsm
{
namespace sdf
{
class SessionPool
{
public:
    SessionPool(int size, void* deviceHandle);
    void* GetSession();
    void ReturnSession(void* session);

private:
    void* m_deviceHandle;
    size_t m_size;
    size_t m_available_session_count;
    std::mutex mtx;
    std::condition_variable cv;
};

/**
 *  SDFCryptoProvider suply SDF function calls
 *  Singleton
 */
class SDFCryptoProvider : public CryptoProvider
{
private:
    void* m_deviceHandle;
    SessionPool* m_sessionPool;
    SDFCryptoProvider();
    SDFCryptoProvider(int sessionPoolSize);
    ~SDFCryptoProvider();
    SDFCryptoProvider(const SDFCryptoProvider&);
    SDFCryptoProvider& operator=(const SDFCryptoProvider&);

public:
    /**
     * Return the instance
     */
    static SDFCryptoProvider& GetInstance();
    static SDFCryptoProvider& GetInstance(int sessionPoolSize);

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

    /**
     * Decrypt
     */
    unsigned int Decrypt(Key const& key, AlgorithmType algorithm, unsigned char* iv,
        unsigned char const* cyphertext, unsigned int cyphertextLen, unsigned char* plantext,
        unsigned int* plantextLen) override;

    /**
     *  Get public key of an internal key
     */
    unsigned int ExportInternalPublicKey(Key& key, AlgorithmType algorithm) override;

    bool generateRandom(unsigned int randomLength, unsigned char* pucRandom);

    char* GetErrorMessage(unsigned int code) override;
    static const unsigned int SM2_BITS;
    static const std::string SM2_USER_ID;
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

SDFCryptoResult KeyGen(AlgorithmType algorithm);
SDFCryptoResult Sign(char* privateKey, AlgorithmType algorithm, char const* digest);
SDFCryptoResult SignWithInternalKey(
    unsigned int keyIndex, char* password, AlgorithmType algorithm, char const* digest);
SDFCryptoResult Verify(
    char* publicKey, AlgorithmType algorithm, char const* digest, char const* signature);
SDFCryptoResult VerifyWithInternalKey(
    unsigned int keyIndex, AlgorithmType algorithm, char const* digest, char const* signature);
SDFCryptoResult Hash(char* key, AlgorithmType algorithm, char const* message);
SDFCryptoResult ExportInternalPublicKey(unsigned int keyIndex, AlgorithmType algorithm);
SDFCryptoResult makeResult(char* signature, char* publicKey, char* privateKey, bool result,
    char* hash, unsigned int code, char*);
char* sdfToHex(const std::vector<byte>& data);
std::vector<byte> sdfFromHex(char* hexString);
int fromHexChar(char _i);
unsigned int getHexByteLen(char* hexString);
int PrintData(char*, unsigned char*, unsigned int, unsigned int);
std::string getSdfErrorMessage(unsigned int code);
}  // namespace sdf
}  // namespace hsm
