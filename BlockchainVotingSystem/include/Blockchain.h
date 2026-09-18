#pragma once

#include "Block.h"
#include <vector>
#include <string>
#include <stdexcept>

/**
 * @brief Custom exception class for blockchain validation and operational errors.
 */
class BlockchainException : public std::runtime_error {
public:
    explicit BlockchainException(const std::string& message)
        : std::runtime_error(message) {}
};

/**
 * @brief Manages the append-only cryptographic ledger of blocks.
 * 
 * Provides automated genesis block initialization, safe block appending,
 * cryptographic verification of chain integrity, and tamper detection.
 */
class Blockchain {
public:
    /**
     * @brief Constructs the blockchain and automatically mines the Genesis Block.
     * 
     * @param difficulty Proof-of-work mining difficulty (number of leading zeros). Defaults to 2.
     */
    explicit Blockchain(uint32_t difficulty = 2);

    /**
     * @brief Replaces the current chain with blocks loaded from external persistent storage.
     * 
     * @param blocks Sequence of reconstructed blocks.
     */
    void loadBlocks(const std::vector<Block>& blocks);

    /**
     * @brief Appends a new block containing the provided transaction payload.
     * 
     * Automatically links the new block to the latest block's hash and mines it.
     * 
     * @param data Payload or transaction string to record in the block.
     * @throws BlockchainException if data payload is empty or invalid.
     */
    void addBlock(const std::string& data);

    /**
     * @brief Computes the cryptographic hash for a given block.
     * 
     * @param block The block whose hash is to be computed.
     * @return 64-character hexadecimal SHA-256 digest string.
     */
    std::string calculateHash(const Block& block) const;

    /**
     * @brief Cryptographically validates the integrity of the entire blockchain.
     * 
     * Verifies:
     * 1. Genesis block validity.
     * 2. Recalculated SHA-256 hash matching recorded hash for every block.
     * 3. Previous hash pointer consistency across all adjacent blocks.
     * 4. Proof-of-work difficulty adherence.
     * 
     * @param outErrorMessage Optional output pointer to receive failure diagnostics.
     * @return true if the entire chain is cryptographically intact; false if tampered or corrupt.
     */
    bool isChainValid(std::string* outErrorMessage = nullptr) const;

    /**
     * @brief Pretty-prints the full sequence of blocks in the blockchain.
     */
    void displayBlockchain() const;

    // Accessors
    const std::vector<Block>& getChain() const noexcept;
    const Block& getLatestBlock() const;
    size_t getChainSize() const noexcept;
    uint32_t getDifficulty() const noexcept;

    // Direct access to modify blocks for tamper simulation & security testing
    Block& getBlockMutable(size_t index);

private:
    std::vector<Block> m_chain;
    uint32_t m_difficulty;

    /**
     * @brief Creates and mines the primordial Genesis Block at index 0.
     * 
     * @return Fully initialized and mined Genesis Block.
     */
    Block createGenesisBlock();
};

