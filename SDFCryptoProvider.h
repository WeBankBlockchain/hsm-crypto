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
#include "libsdf/swsds.h"

using namespace std;
namespace dev
{
class KeyPair;
namespace crypto
{
enum AlgorithmType : uint32_t
{
    SM2 = 0x00020100,      // SGD_SM2_1
    SM3 = 0x00000001,      // SGD_SM3
    SM4_CBC = 0x00002002,  // SGD_SM4_CBC
};

class Key
{
public:
    char* PublicKey() const { return m_publicKey; }
    char* PrivateKey() const { return m_privateKey; }
    Key(void){};
    Key(char* privateKey, char* publicKey)
    {
        m_privateKey = privateKey;
        m_publicKey = publicKey;
    };
    Key(const unsigned int keyIndex, char *& password)
    {
        m_keyIndex = keyIndex;
        m_keyPassword = password;
    };
    unsigned int Identifier() { return m_keyIndex; };
    char * Password() { return m_keyPassword; };
    void setPrivateKey(char* privateKey, unsigned int len)
    {
        m_privateKey = (char*)malloc(len * sizeof(char));
        strncpy((char*)m_privateKey, (char*)privateKey, len);
    };
    void setPublicKey(char* publicKey, unsigned int len)
    {
        m_publicKey = (char*)malloc(len * sizeof(char));
        strncpy((char*)m_publicKey, (char*)publicKey, len);
    };

private:
    unsigned int m_keyIndex;
    char * m_keyPassword;
    char* m_privateKey;
    char* m_publicKey;
};

class SessionPool
{
public:
    SessionPool(int size, void * deviceHandle);
    virtual ~SessionPool();
    void * GetSession();
    void ReturnSession(void * session);


private:
    void * m_deviceHandle;
    size_t m_size;
    std::list<void *> m_pool;
};

/**
 *  SDFCryptoProvider suply SDF function calls
 *  Singleton
 */
class SDFCryptoProvider
{
private:
    void * m_deviceHandle;
    SessionPool* m_sessionPool;
    SDFCryptoProvider();
    ~SDFCryptoProvider();
    SDFCryptoProvider(const SDFCryptoProvider&);
    SDFCryptoProvider& operator=(const SDFCryptoProvider&);
    // std::mutex mut;

public:
    /**
     * Return the instance
     */
    static SDFCryptoProvider& GetInstance();

    /**
     * Generate key
     * Return error code
     */
    unsigned int KeyGen(AlgorithmType algorithm, Key* key);

    /**
     * Sign
     */
    unsigned int Sign(Key const& key, AlgorithmType algorithm, char const* digest,
        unsigned int const digestLen, char* signature, unsigned int* signatureLen);

    /**
     * Verify signature
     */
    unsigned int Verify(Key const& key, AlgorithmType algorithm, char const* digest,
        unsigned int const digestLen, char const* signature,
        unsigned int const signatureLen, bool* result);

    /**
     * Make hash
     */
    unsigned int Hash(Key* key, AlgorithmType algorithm, char const* message,
        unsigned int const messageLen, char* digest, unsigned int* digestLen);

    /**
     * Encrypt
     */
    unsigned int Encrypt(Key const& key, AlgorithmType algorithm, char const* plantext,
        unsigned int const plantextLen, char* cyphertext, unsigned int* cyphertextLen);

    /**
     * Decrypt
     */
    unsigned int Decrypt(Key const& key, AlgorithmType algorithm, char const* cyphertext,
        unsigned int const cyphertextLen, char* plantext, unsigned int* plantextLen);

    /**
     * Make sm3 hash with z value
     */
    unsigned int HashWithZ(Key* key, AlgorithmType algorithm, char const* zValue,
        unsigned int const zValueLen, char const* message, unsigned int const messageLen,
        char* digest, unsigned int* digestLen);

    static char * GetErrorMessage(unsigned int code);
};

class TypeHelper{
    unsigned int * NewUintPointer(){
        unsigned int i;
        return &i;
    }

    unsigned int GetUintValue(unsigned int * data){
        return *data;
    }

    bool* NewBoolPointer(){
        bool i;
        return &i;
    }

    bool GetBoolValue(bool * data){
        return *data;
    }
};

}  // namespace crypto
}  // namespace dev
