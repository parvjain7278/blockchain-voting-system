#pragma once

#include <string>
#include <vector>
#include <stdexcept>
#include <cstdint>

namespace Crypto {

/**
 * @brief Custom exception thrown when a cryptographic operation fails.
 */
class CryptoException : public std::runtime_error {
public:
    explicit CryptoException(const std::string& message)
        : std::runtime_error(message) {}
};

// ============================================================================
// 1. HASHING SUBSYSTEM
// ============================================================================

/**
 * @brief Computes standard NIST FIPS 180-2 SHA-256 cryptographic hash of the input.
 * 
 * Uses Windows Cryptographic Service Provider (CryptoAPI via advapi32).
 * 
 * @param input Plain text or binary input string.
 * @return 64-character lowercase hexadecimal hash digest.
 */
std::string sha256(const std::string& input);

/**
 * @brief Generates cryptographically secure random bytes as a hexadecimal salt.
 * 
 * Uses Windows CryptoAPI CryptGenRandom (CSPRNG).
 * 
 * @param byteCount Number of random bytes to generate (defaults to 16, resulting in 32 hex chars).
 * @return Hexadecimal encoded random salt string.
 */
std::string generateRandomHexSalt(size_t byteCount = 16);

/**
 * @brief Performs constant-time comparison of two strings to prevent timing side-channel attacks.
 * 
 * @return true if strings are identical; false otherwise.
 */
bool constantTimeEquals(const std::string& a, const std::string& b);


// ============================================================================
// 2. ENCRYPTION / CONFIDENTIALITY SUBSYSTEM (OPTIONAL / SEPARATE)
// ============================================================================

/**
 * @brief Demonstrates clear modular separation between confidentiality (encryption)
 * and authenticity / non-repudiation (digital signatures).
 */
namespace Confidentiality {
    // Reserved for future payload encryption if voter privacy requirements expand.
}


// ============================================================================
// 3. DIGITAL SIGNATURES SUBSYSTEM (ASYMMETRIC PUBLIC-KEY CRYPTOGRAPHY)
// ============================================================================

/**
 * @brief Asymmetric cryptographic key pair.
 * 
 * Public key is shared openly to verify signatures.
 * Private key must remain strictly confidential and protected by the voter.
 */
struct KeyPair {
    std::string publicKey;  ///< Hex-encoded public key (PUBLICKEYBLOB)
    std::string privateKey; ///< Hex-encoded private key (PRIVATEKEYBLOB)
};

/**
 * @brief Generates a new secure asymmetric RSA key pair using Windows CryptoAPI CSPRNG.
 * 
 * @param keyBits Key length in bits (default 2048, or 1024 for rapid testing).
 * @return KeyPair struct containing hex-encoded public and private keys.
 */
KeyPair generateKeyPair(uint32_t keyBits = 2048);

/**
 * @brief Digitally signs a serialized transaction payload using an asymmetric private key.
 * 
 * Computes SHA-256 hash of transaction data and creates an RSA digital signature.
 * 
 * @param serializedTransaction Canonical string representation of the transaction.
 * @param privateKeyHex Hex-encoded private key.
 * @return Hex-encoded digital signature string.
 * @throws CryptoException if signing fails.
 */
std::string signTransaction(const std::string& serializedTransaction, const std::string& privateKeyHex);

/**
 * @brief Verifies the authenticity and integrity of a transaction digital signature.
 * 
 * Recalculates SHA-256 hash of transaction data and verifies the signature using the public key.
 * 
 * @param serializedTransaction Canonical string representation of the transaction.
 * @param signatureHex Hex-encoded digital signature to verify.
 * @param publicKeyHex Hex-encoded public key of the signer.
 * @return true if the signature is authentic and unaltered; false otherwise.
 */
bool verifySignature(const std::string& serializedTransaction, 
                     const std::string& signatureHex, 
                     const std::string& publicKeyHex);

} // namespace Crypto

// Top-level aliases for direct access
using Crypto::KeyPair;
using Crypto::generateKeyPair;
using Crypto::signTransaction;
using Crypto::verifySignature;

