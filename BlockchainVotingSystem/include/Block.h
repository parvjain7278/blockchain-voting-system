#pragma once

#include <string>
#include <cstdint>

/**
 * @brief Represents an individual immutable block in the blockchain.
 * 
 * Each block records transactional voting data, a chronological timestamp,
 * its position index, proof-of-work nonce, cryptographic hash, and the
 * hash of the immediately preceding block.
 */
class Block {
public:
    /**
     * @brief Constructs a new Block with the given parameters.
     * 
     * @param index Sequential height position of the block.
     * @param data Payload data (e.g. encrypted voting transaction).
     * @param previousHash Cryptographic hash of the parent block.
     */
    Block(uint32_t index, const std::string& data, const std::string& previousHash);

    /**
     * @brief Constructs a Block with pre-existing metadata (used during ledger deserialization).
     */
    Block(uint32_t index, 
          const std::string& timestamp, 
          const std::string& data, 
          const std::string& previousHash, 
          const std::string& hash, 
          uint64_t nonce);

    /**
     * @brief Computes the SHA-256 hash digest over the block's serialized header.
     * 
     * Serializes: index + timestamp + data + previousHash + nonce.
     * 
     * @return 64-character hexadecimal SHA-256 digest string.
     */
    std::string calculateHash() const;

    /**
     * @brief Mines the block by adjusting nonce until the hash satisfies difficulty prefix.
     * 
     * @param difficulty Number of leading zeros required in the hash digest.
     */
    void mineBlock(uint32_t difficulty);

    // Getters
    uint32_t getIndex() const noexcept;
    const std::string& getTimestamp() const noexcept;
    const std::string& getData() const noexcept;
    const std::string& getPreviousHash() const noexcept;
    const std::string& getHash() const noexcept;
    uint64_t getNonce() const noexcept;

    // Simulation / testing tampering detection
    void setTamperedData(const std::string& newData);
    void setTamperedHash(const std::string& newHash);

    // Formatted display
    void displayBlock() const;

private:
    uint32_t m_index;
    std::string m_timestamp;
    std::string m_data;
    std::string m_previousHash;
    std::string m_hash;
    uint64_t m_nonce;

    /**
     * @brief Generates an ISO 8601 UTC timestamp string.
     */
    static std::string generateCurrentTimestamp();
};

