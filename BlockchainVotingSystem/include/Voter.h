#pragma once

#include "Crypto.h"
#include <string>

/**
 * @brief Represents an authorized voter identity in the election system.
 * 
 * Protects voter anonymity using cryptographic pseudonym hashing while
 * maintaining asymmetric key pairs for signing transactions.
 */
class Voter {
public:
    /**
     * @brief Constructs a new Voter identity and generates an asymmetric key pair.
     * 
     * @param voterId Plaintext voter ID (e.g. national ID or student ID).
     * @param salt Election-specific cryptographic salt to protect voter identity.
     */
    explicit Voter(const std::string& voterId = "", 
                   const std::string& salt = "ELECTION_SECRET_SALT_2026");

    // Getters
    const std::string& getVoterId() const noexcept;
    const std::string& getVoterHash() const noexcept;
    bool hasVoted() const noexcept;

    // Cryptographic Key Management
    const std::string& getPublicKey() const noexcept;
    const std::string& getPrivateKey() const noexcept;
    const Crypto::KeyPair& getKeyPair() const noexcept;
    void setKeyPair(const Crypto::KeyPair& keyPair);

    /**
     * @brief Marks this voter as having cast a ballot.
     */
    void markAsVoted();

    /**
     * @brief Computes a cryptographic pseudonym for a voter ID.
     */
    static std::string generateVoterHash(const std::string& voterId, const std::string& salt);

private:
    std::string m_voterId;
    std::string m_voterHash;
    bool m_hasVoted;
    Crypto::KeyPair m_keyPair;
};
