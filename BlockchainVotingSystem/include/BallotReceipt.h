#pragma once

#include "Blockchain.h"
#include <string>
#include <cstdint>

/**
 * @brief Represents an individual voter verification receipt.
 * 
 * In modern cryptographic e-voting systems, voters receive an audit receipt
 * that proves their ballot is permanently recorded in a specific block on
 * the blockchain ledger, without revealing which candidate they voted for.
 */
class BallotReceipt {
public:
    BallotReceipt(const std::string& ballotId, 
                  const std::string& voterHash, 
                  uint32_t blockIndex, 
                  const std::string& blockHash);

    /**
     * @brief Cryptographically verifies that this ballot exists unchanged on the blockchain.
     * 
     * @param chain The blockchain instance to verify against.
     * @param outStatusMessage Optional diagnostic message pointer.
     * @return true if verified on-chain; false if missing or block tampered.
     */
    bool verifyOnChain(const Blockchain& chain, std::string* outStatusMessage = nullptr) const;

    // Getters
    const std::string& getBallotId() const noexcept;
    const std::string& getVoterHash() const noexcept;
    uint32_t getBlockIndex() const noexcept;
    const std::string& getBlockHash() const noexcept;
    const std::string& getReceiptCode() const noexcept;

    void displayReceipt() const;

private:
    std::string m_ballotId;
    std::string m_voterHash;
    uint32_t m_blockIndex;
    std::string m_blockHash;
    std::string m_receiptCode;

    std::string computeReceiptCode() const;
};

