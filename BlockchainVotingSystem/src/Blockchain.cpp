#include "Blockchain.h"
#include <iostream>

Blockchain::Blockchain(uint32_t difficulty)
    : m_difficulty(difficulty) {
    // Automatically create and mine the Genesis Block upon instantiation
    m_chain.push_back(createGenesisBlock());
}

void Blockchain::loadBlocks(const std::vector<Block>& blocks) {
    if (blocks.empty()) {
        throw BlockchainException("Cannot load empty block set into blockchain.");
    }
    m_chain = blocks;
}

Block Blockchain::createGenesisBlock() {
    Block genesis(0, 
                  "GENESIS_BLOCK: Secure Electronic Voting System Initialized", 
                  "0000000000000000000000000000000000000000000000000000000000000000");
    genesis.mineBlock(m_difficulty);
    return genesis;
}

const Block& Blockchain::getLatestBlock() const {
    if (m_chain.empty()) {
        throw BlockchainException("Blockchain is empty; cannot access latest block.");
    }
    return m_chain.back();
}

void Blockchain::addBlock(const std::string& data) {
    if (data.empty()) {
        throw BlockchainException("Failed to add block: data payload cannot be empty.");
    }

    const std::string& prevHash = getLatestBlock().getHash();
    uint32_t nextIndex = static_cast<uint32_t>(m_chain.size());
    Block newBlock(nextIndex, data, prevHash);
    newBlock.mineBlock(m_difficulty);
    m_chain.push_back(newBlock);
}

std::string Blockchain::calculateHash(const Block& block) const {
    return block.calculateHash();
}

bool Blockchain::isChainValid(std::string* outErrorMessage) const {
    if (m_chain.empty()) {
        if (outErrorMessage) *outErrorMessage = "Blockchain has no blocks.";
        return false;
    }

    // 1. Validate Genesis Block
    const Block& genesis = m_chain[0];
    if (genesis.getIndex() != 0) {
        if (outErrorMessage) {
            *outErrorMessage = "Invalid genesis block: index must be 0.";
        }
        return false;
    }

    if (genesis.getHash() != genesis.calculateHash()) {
        if (outErrorMessage) {
            *outErrorMessage = "Genesis block hash corrupt! Recorded: " + genesis.getHash() 
                             + " | Calculated: " + genesis.calculateHash();
        }
        return false;
    }

    // 2. Validate all subsequent blocks in sequence
    for (size_t i = 1; i < m_chain.size(); ++i) {
        const Block& currentBlock = m_chain[i];
        const Block& previousBlock = m_chain[i - 1];

        // Verify index sequence
        if (currentBlock.getIndex() != i) {
            if (outErrorMessage) {
                *outErrorMessage = "Index discontinuity at Block #" + std::to_string(i) 
                                 + ": expected index " + std::to_string(i) 
                                 + ", found " + std::to_string(currentBlock.getIndex());
            }
            return false;
        }

        // Verify current block hash integrity (tamper detection)
        std::string recalculatedHash = currentBlock.calculateHash();
        if (currentBlock.getHash() != recalculatedHash) {
            if (outErrorMessage) {
                *outErrorMessage = "Tampering detected at Block #" + std::to_string(i) 
                                 + "! Stored hash: " + currentBlock.getHash() 
                                 + " | Recalculated hash: " + recalculatedHash;
            }
            return false;
        }

        // Verify cryptographic linkage to the parent block's hash
        if (currentBlock.getPreviousHash() != previousBlock.getHash()) {
            if (outErrorMessage) {
                *outErrorMessage = "Cryptographic chain broken between Block #" + std::to_string(i - 1) 
                                 + " and Block #" + std::to_string(i) 
                                 + "! Recorded previousHash: " + currentBlock.getPreviousHash() 
                                 + " | Actual parent hash: " + previousBlock.getHash();
            }
            return false;
        }

        // Verify proof of work condition
        std::string targetPrefix(m_difficulty, '0');
        if (currentBlock.getHash().substr(0, m_difficulty) != targetPrefix) {
            if (outErrorMessage) {
                *outErrorMessage = "Difficulty constraint unsatisfied at Block #" + std::to_string(i);
            }
            return false;
        }
    }

    return true;
}

void Blockchain::displayBlockchain() const {
    std::cout << "\n====================================================================================================\n";
    std::cout << "                                  BLOCKCHAIN LEDGER OVERVIEW                                         \n";
    std::cout << "                     Total Blocks: " << m_chain.size() 
              << " | Difficulty: " << m_difficulty << " leading zeros\n";
    std::cout << "====================================================================================================\n\n";

    for (size_t i = 0; i < m_chain.size(); ++i) {
        m_chain[i].displayBlock();
        if (i + 1 < m_chain.size()) {
            std::cout << "                                                 |\n";
            std::cout << "                                                 | (SHA-256 Link)\n";
            std::cout << "                                                 v\n";
        }
    }
    std::cout << "\n====================================================================================================\n\n";
}

const std::vector<Block>& Blockchain::getChain() const noexcept {
    return m_chain;
}

size_t Blockchain::getChainSize() const noexcept {
    return m_chain.size();
}

uint32_t Blockchain::getDifficulty() const noexcept {
    return m_difficulty;
}

Block& Blockchain::getBlockMutable(size_t index) {
    if (index >= m_chain.size()) {
        throw BlockchainException("Block index out of range: " + std::to_string(index));
    }
    return m_chain[index];
}

