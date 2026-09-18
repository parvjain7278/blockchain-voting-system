#pragma once

#include <string>

/**
 * @brief Represents a cryptographically authenticated ballot transaction.
 * 
 * Each vote contains an anonymous cryptographic voter hash, candidate selection,
 * chronological timestamp, voter public key, and asymmetric digital signature.
 */
class Vote {
public:
    /**
     * @brief Constructs an unsigned Vote transaction (or legacy signed if no key supplied).
     * 
     * @param ballotId Unique ballot identifier.
     * @param voterHash Pseudonymous cryptographic hash of the voter.
     * @param candidate Name or ID of the selected candidate.
     * @param timestamp Optional ISO timestamp (defaults to current time if empty).
     */
    Vote(const std::string& ballotId, 
         const std::string& voterHash, 
         const std::string& candidate, 
         const std::string& timestamp = "");

    /**
     * @brief Constructs a fully signed Vote transaction with public key and digital signature.
     */
    Vote(const std::string& ballotId, 
         const std::string& voterHash, 
         const std::string& candidate, 
         const std::string& timestamp,
         const std::string& publicKey,
         const std::string& signature);

    /**
     * @brief Returns the canonical serialized transaction data payload to be digitally signed.
     * Format: ballotId:voterHash:candidate:timestamp
     */
    std::string getPayloadToSign() const;

    /**
     * @brief Signs this transaction using the voter's private key.
     * 
     * @param privateKeyHex Hex-encoded RSA private key.
     */
    void sign(const std::string& privateKeyHex);

    /**
     * @brief Verifies the digital signature of this transaction.
     * 
     * @param publicKeyHex Hex-encoded public key. If omitted/empty, uses m_publicKey.
     * @return true if valid; false otherwise.
     */
    bool verifySignature(const std::string& publicKeyHex = "") const;

    /**
     * @brief Serializes the vote transaction into a delimited format for block payload storage.
     */
    std::string serialize() const;

    /**
     * @brief Deserializes a raw block payload into a Vote instance.
     * 
     * Supports both 7-field digitally signed transactions and 6-field legacy records.
     * 
     * @param raw Serialized payload string.
     * @return Reconstructed Vote instance.
     */
    static Vote deserialize(const std::string& raw);

    /**
     * @brief Checks if raw block payload is a serialized Vote transaction.
     */
    static bool isVotePayload(const std::string& raw);

    /**
     * @brief Verifies the cryptographic integrity of this ballot.
     * 
     * @return true if digital signature (or legacy signature) is valid.
     */
    bool isValid() const;

    // Getters and Setters
    const std::string& getBallotId() const noexcept;
    const std::string& getVoterHash() const noexcept;
    const std::string& getCandidate() const noexcept;
    const std::string& getTimestamp() const noexcept;
    const std::string& getPublicKey() const noexcept;
    const std::string& getSignature() const noexcept;

    void setPublicKey(const std::string& publicKey);
    void setSignature(const std::string& signature);

private:
    std::string m_ballotId;
    std::string m_voterHash;
    std::string m_candidate;
    std::string m_timestamp;
    std::string m_publicKey;
    std::string m_signature;

    std::string computeHashSignature() const;
    static std::string generateCurrentTimestamp();
};
