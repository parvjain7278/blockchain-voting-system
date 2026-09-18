#include "Crypto.h"

#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#include <windows.h>
#include <wincrypt.h>

#ifndef CALG_SHA_256
#define CALG_SHA_256 0x0000800c
#endif

#ifndef PROV_RSA_AES
#define PROV_RSA_AES 24
#endif
#endif

#include <iomanip>
#include <sstream>
#include <vector>
#include <cstdio>
#include <cctype>

namespace Crypto {

// Helper: Convert binary buffer to lowercase hexadecimal string
static std::string bytesToHex(const BYTE* data, size_t length) {
    std::string hex;
    hex.reserve(length * 2);
    char buf[3];
    for (size_t i = 0; i < length; ++i) {
        std::snprintf(buf, sizeof(buf), "%02x", data[i]);
        hex += buf;
    }
    return hex;
}

// Helper: Convert hexadecimal string to binary buffer
static std::vector<BYTE> hexToBytes(const std::string& hex) {
    if (hex.length() % 2 != 0) {
        return {};
    }
    std::vector<BYTE> bytes;
    bytes.reserve(hex.length() / 2);
    for (size_t i = 0; i < hex.length(); i += 2) {
        char high = hex[i];
        char low = hex[i + 1];
        if (!std::isxdigit(static_cast<unsigned char>(high)) || 
            !std::isxdigit(static_cast<unsigned char>(low))) {
            return {};
        }
        unsigned int byteVal = 0;
        std::sscanf(hex.substr(i, 2).c_str(), "%x", &byteVal);
        bytes.push_back(static_cast<BYTE>(byteVal));
    }
    return bytes;
}

// ============================================================================
// 1. HASHING SUBSYSTEM IMPLEMENTATION
// ============================================================================

std::string sha256(const std::string& input) {
#ifdef _WIN32
    HCRYPTPROV hProv = 0;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        throw CryptoException("Failed to acquire Windows Cryptographic Provider (PROV_RSA_AES). Error code: " 
                              + std::to_string(GetLastError()));
    }

    HCRYPTHASH hHash = 0;
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        DWORD err = GetLastError();
        CryptReleaseContext(hProv, 0);
        throw CryptoException("Failed to create SHA-256 hash object. Error code: " + std::to_string(err));
    }

    BYTE* dataPtr = reinterpret_cast<BYTE*>(const_cast<char*>(input.data()));
    DWORD dataLen = static_cast<DWORD>(input.size());

    if (!CryptHashData(hHash, dataPtr, dataLen, 0)) {
        DWORD err = GetLastError();
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        throw CryptoException("CryptHashData failed. Error code: " + std::to_string(err));
    }

    DWORD hashLen = 32;
    BYTE hashBuffer[32];
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hashBuffer, &hashLen, 0)) {
        DWORD err = GetLastError();
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        throw CryptoException("CryptGetHashParam failed. Error code: " + std::to_string(err));
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    return bytesToHex(hashBuffer, 32);
#else
    #error "Platform cryptographic provider is not configured for non-Windows platforms."
#endif
}

std::string generateRandomHexSalt(size_t byteCount) {
#ifdef _WIN32
    HCRYPTPROV hProv = 0;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        throw CryptoException("Failed to acquire CSP context for CSPRNG salt generation.");
    }
    std::vector<BYTE> buffer(byteCount);
    if (!CryptGenRandom(hProv, static_cast<DWORD>(byteCount), buffer.data())) {
        CryptReleaseContext(hProv, 0);
        throw CryptoException("CryptGenRandom failed to generate random bytes.");
    }
    CryptReleaseContext(hProv, 0);

    return bytesToHex(buffer.data(), byteCount);
#else
    #error "Platform cryptographic provider is not configured for non-Windows platforms."
#endif
}

bool constantTimeEquals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) {
        return false;
    }
    unsigned char diff = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        diff |= static_cast<unsigned char>(a[i] ^ b[i]);
    }
    return diff == 0;
}

// ============================================================================
// 3. DIGITAL SIGNATURES SUBSYSTEM IMPLEMENTATION
// ============================================================================

KeyPair generateKeyPair(uint32_t keyBits) {
#ifdef _WIN32
    HCRYPTPROV hProv = 0;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        throw CryptoException("CryptAcquireContext failed in generateKeyPair. Error: " 
                              + std::to_string(GetLastError()));
    }

    HCRYPTKEY hKey = 0;
    // Generate RSA key pair with signature capability and exportability
    DWORD flags = (keyBits << 16) | CRYPT_EXPORTABLE;
    if (!CryptGenKey(hProv, AT_SIGNATURE, flags, &hKey)) {
        DWORD err = GetLastError();
        CryptReleaseContext(hProv, 0);
        throw CryptoException("CryptGenKey failed to generate RSA key pair. Error: " + std::to_string(err));
    }

    // 1. Export Public Key (PUBLICKEYBLOB)
    DWORD pubKeyLen = 0;
    CryptExportKey(hKey, 0, PUBLICKEYBLOB, 0, NULL, &pubKeyLen);
    std::vector<BYTE> pubKeyBytes(pubKeyLen);
    if (!CryptExportKey(hKey, 0, PUBLICKEYBLOB, 0, pubKeyBytes.data(), &pubKeyLen)) {
        DWORD err = GetLastError();
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        throw CryptoException("CryptExportKey failed for public key. Error: " + std::to_string(err));
    }

    // 2. Export Private Key (PRIVATEKEYBLOB)
    DWORD privKeyLen = 0;
    CryptExportKey(hKey, 0, PRIVATEKEYBLOB, 0, NULL, &privKeyLen);
    std::vector<BYTE> privKeyBytes(privKeyLen);
    if (!CryptExportKey(hKey, 0, PRIVATEKEYBLOB, 0, privKeyBytes.data(), &privKeyLen)) {
        DWORD err = GetLastError();
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        throw CryptoException("CryptExportKey failed for private key. Error: " + std::to_string(err));
    }

    CryptDestroyKey(hKey);
    CryptReleaseContext(hProv, 0);

    KeyPair kp;
    kp.publicKey = bytesToHex(pubKeyBytes.data(), pubKeyBytes.size());
    kp.privateKey = bytesToHex(privKeyBytes.data(), privKeyBytes.size());
    return kp;
#else
    #error "Platform cryptographic provider is not configured for non-Windows platforms."
#endif
}

std::string signTransaction(const std::string& serializedTransaction, const std::string& privateKeyHex) {
#ifdef _WIN32
    std::vector<BYTE> privKeyBytes = hexToBytes(privateKeyHex);
    if (privKeyBytes.empty()) {
        throw CryptoException("signTransaction failed: Invalid or empty private key hex.");
    }

    HCRYPTPROV hProv = 0;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        throw CryptoException("CryptAcquireContext failed in signTransaction. Error: " 
                              + std::to_string(GetLastError()));
    }

    // Import private key
    HCRYPTKEY hKey = 0;
    if (!CryptImportKey(hProv, privKeyBytes.data(), static_cast<DWORD>(privKeyBytes.size()), 0, 0, &hKey)) {
        DWORD err = GetLastError();
        CryptReleaseContext(hProv, 0);
        throw CryptoException("CryptImportKey failed to import private key. Error: " + std::to_string(err));
    }

    // Hash transaction data using SHA-256
    HCRYPTHASH hHash = 0;
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        DWORD err = GetLastError();
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        throw CryptoException("CryptCreateHash failed in signTransaction. Error: " + std::to_string(err));
    }

    BYTE* dataPtr = reinterpret_cast<BYTE*>(const_cast<char*>(serializedTransaction.data()));
    DWORD dataLen = static_cast<DWORD>(serializedTransaction.size());
    if (!CryptHashData(hHash, dataPtr, dataLen, 0)) {
        DWORD err = GetLastError();
        CryptDestroyHash(hHash);
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        throw CryptoException("CryptHashData failed in signTransaction. Error: " + std::to_string(err));
    }

    // Sign the SHA-256 hash using the private key
    DWORD sigLen = 0;
    CryptSignHash(hHash, AT_SIGNATURE, NULL, 0, NULL, &sigLen);
    std::vector<BYTE> sigBytes(sigLen);
    if (!CryptSignHash(hHash, AT_SIGNATURE, NULL, 0, sigBytes.data(), &sigLen)) {
        DWORD err = GetLastError();
        CryptDestroyHash(hHash);
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        throw CryptoException("CryptSignHash failed. Error: " + std::to_string(err));
    }

    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);
    CryptReleaseContext(hProv, 0);

    return bytesToHex(sigBytes.data(), sigBytes.size());
#else
    #error "Platform cryptographic provider is not configured for non-Windows platforms."
#endif
}

bool verifySignature(const std::string& serializedTransaction, 
                     const std::string& signatureHex, 
                     const std::string& publicKeyHex) {
#ifdef _WIN32
    if (serializedTransaction.empty() || signatureHex.empty() || publicKeyHex.empty()) {
        return false;
    }

    std::vector<BYTE> pubKeyBytes = hexToBytes(publicKeyHex);
    std::vector<BYTE> sigBytes = hexToBytes(signatureHex);
    if (pubKeyBytes.empty() || sigBytes.empty()) {
        return false;
    }

    HCRYPTPROV hProv = 0;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return false;
    }

    // Import public key
    HCRYPTKEY hPubKey = 0;
    if (!CryptImportKey(hProv, pubKeyBytes.data(), static_cast<DWORD>(pubKeyBytes.size()), 0, 0, &hPubKey)) {
        CryptReleaseContext(hProv, 0);
        return false;
    }

    // Recreate SHA-256 hash of transaction data
    HCRYPTHASH hHash = 0;
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptDestroyKey(hPubKey);
        CryptReleaseContext(hProv, 0);
        return false;
    }

    BYTE* dataPtr = reinterpret_cast<BYTE*>(const_cast<char*>(serializedTransaction.data()));
    DWORD dataLen = static_cast<DWORD>(serializedTransaction.size());
    if (!CryptHashData(hHash, dataPtr, dataLen, 0)) {
        CryptDestroyHash(hHash);
        CryptDestroyKey(hPubKey);
        CryptReleaseContext(hProv, 0);
        return false;
    }

    // Verify signature with public key
    BOOL ok = CryptVerifySignature(hHash, 
                                   sigBytes.data(), 
                                   static_cast<DWORD>(sigBytes.size()), 
                                   hPubKey, 
                                   NULL, 
                                   0);

    CryptDestroyHash(hHash);
    CryptDestroyKey(hPubKey);
    CryptReleaseContext(hProv, 0);

    return (ok == TRUE);
#else
    #error "Platform cryptographic provider is not configured for non-Windows platforms."
#endif
}

} // namespace Crypto

