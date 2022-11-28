#pragma once
#include "Common.h"
#include <stdio.h>
#include <cstdlib>
#include <cstring>
#include <list>
#include <string>
#include <vector>
#include <memory>

namespace hsm
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
    Key() = default;

    Key(std::shared_ptr<const std::vector<byte> > privateKey,
        std::shared_ptr<const std::vector<byte> > publicKey)
    {
        m_publicKey = publicKey;
        m_privateKey = privateKey;
    };

    Key(unsigned int keyIndex, std::shared_ptr<const std::vector<byte> > password)
    {
        m_keyIndex = keyIndex;
        m_keyPassword = password;
        m_isInternalKey = true;
    };
    Key(unsigned int keyIndex)
    {
        m_keyIndex = keyIndex;
        m_isInternalKey = true;
    };
    void setPrivateKey(std::shared_ptr<const std::vector<byte> > privateKey)
    {
        m_privateKey = privateKey;
    };
    void setPublicKey(std::shared_ptr<const std::vector<byte> > publicKey) { m_publicKey = publicKey; };
    void setSymmetricKey(std::shared_ptr<const std::vector<byte> > symmetricKey)
    {
        m_symmetricKey = symmetricKey;
    };
    std::shared_ptr<const std::vector<byte> > publicKey() const { return m_publicKey; }
    std::shared_ptr<const std::vector<byte> > privateKey() const { return m_privateKey; }
    std::shared_ptr<const std::vector<byte> > symmetrickey() const { return m_symmetricKey; }
    unsigned int identifier() const { return m_keyIndex; };
    std::shared_ptr<const std::vector<byte> > password() const { return m_keyPassword; };
    bool isInternalKey() const { return m_isInternalKey; }

private:
    std::shared_ptr<const std::vector<byte> > m_publicKey;
    std::shared_ptr<const std::vector<byte> > m_privateKey;
    std::shared_ptr<const std::vector<byte> > m_keyPassword;
    std::shared_ptr<const std::vector<byte> > m_symmetricKey;
    unsigned int m_keyIndex;
    bool m_isInternalKey = false;
};

class CryptoProvider
{
public:
    /**
     * Generate key
     * Return error code
     */
    virtual unsigned int KeyGen(AlgorithmType algorithm, Key* key) = 0;

    /**
     * Sign
     */
    virtual unsigned int Sign(Key const& key, AlgorithmType algorithm, unsigned char const* digest,
        unsigned int digestLen, unsigned char* signature, unsigned int* signatureLen) = 0;

    /**
     * Verify signature
     */
    virtual unsigned int Verify(Key const& key, AlgorithmType algorithm,
        unsigned char const* digest, unsigned int digestLen, unsigned char const* signature,
        unsigned int signatureLen, bool* result) = 0;

    /**
     * Make hash
     */
    virtual unsigned int Hash(Key* key, AlgorithmType algorithm, unsigned char const* message,
        unsigned int messageLen, unsigned char* digest, unsigned int* digestLen) = 0;

    /**
     * Encrypt
     */
    virtual unsigned int Encrypt(Key const& key, AlgorithmType algorithm, unsigned char* iv,
        unsigned char const* plantext, unsigned int plantextLen, unsigned char* cyphertext,
        unsigned int* cyphertextLen) = 0;

    /**
     * Decrypt
     */
    virtual unsigned int Decrypt(Key const& key, AlgorithmType algorithm, unsigned char* iv,
        unsigned char const* cyphertext, unsigned int cyphertextLen, unsigned char* plantext,
        unsigned int* plantextLen) = 0;

    /**
     *  Get public key of an internal key
     */
    virtual unsigned int ExportInternalPublicKey(Key& key, AlgorithmType algorithm) = 0;

    virtual char* GetErrorMessage(unsigned int code) = 0;
};
}  // namespace hsm