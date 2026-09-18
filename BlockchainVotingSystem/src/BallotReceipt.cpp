#include "BallotReceipt.h"
#include "Vote.h"
#include "CryptoUtils.h"
#include <iostream>
#include <iomanip>
#include <sstream>

BallotReceipt::BallotReceipt(const std::string& ballotId, 
                             const std::string& voterHash, 
                             uint32_t blockIndex, 
                             const std::string& blockHash)
    : m_ballotId(ballotId),
      m_voterHash(voterHash),
      m_blockIndex(blockIndex),
      m_blockHash(blockHash),
      m_receiptCode("") {
    m_receiptCode = computeReceiptCode();
}

std::string BallotReceipt::computeReceiptCode() const {
    std::ostringstream ss;
    ss << "RECEIPT|" 
       << m_ballotId << "|" 
       << m_voterHash << "|" 
       << m_blockIndex << "|" 
       << m_blockHash;
    return Crypto::sha256(ss.str());
}

bool BallotReceipt::verifyOnChain(const Blockchain& chain, std::string* outStatusMessage) const {
    if (m_receiptCode != computeReceiptCode()) {
        if (outStatusMessage) *outStatusMessage = "Receipt verification failed: Invalid or forged receipt code.";
        return false;
    }

    if (m_blockIndex >= chain.getChainSize()) {
        if (outStatusMessage) *outStatusMessage = "Receipt verification failed: Block index out of blockchain bounds.";
        return false;
    }

    const Block& targetBlock = chain.getChain()[m_blockIndex];

    // Verify block hash matches receipt
    if (targetBlock.getHash() != m_blockHash) {
        if (outStatusMessage) *outStatusMessage = "Receipt verification failed: Block hash on blockchain does not match receipt hash.";
        return false;
    }

    // Verify block payload contains this ballot
    if (!Vote::isVotePayload(targetBlock.getData())) {
        if (outStatusMessage) *outStatusMessage = "Receipt verification failed: Target block does not contain a ballot transaction.";
        return false;
    }

    try {
        Vote vote = Vote::deserialize(targetBlock.getData());
        if (vote.getBallotId() != m_ballotId || vote.getVoterHash() != m_voterHash) {
            if (outStatusMessage) *outStatusMessage = "Receipt verification failed: Ballot ID or voter pseudonym does not match block payload.";
            return false;
        }

        if (!vote.isValid()) {
            if (outStatusMessage) *outStatusMessage = "Receipt verification failed: Ballot cryptographic signature is corrupted.";
            return false;
        }
    } catch (const std::exception& ex) {
        if (outStatusMessage) *outStatusMessage = std::string("Receipt verification error: ") + ex.what();
        return false;
    }

    if (outStatusMessage) {
        *outStatusMessage = "VERIFIED: Ballot " + m_ballotId + " is cryptographically confirmed in Block #" 
                            + std::to_string(m_blockIndex) + " on the blockchain ledger.";
    }
    return true;
}

const std::string& BallotReceipt::getBallotId() const noexcept {
    return m_ballotId;
}

const std::string& BallotReceipt::getVoterHash() const noexcept {
    return m_voterHash;
}

uint32_t BallotReceipt::getBlockIndex() const noexcept {
    return m_blockIndex;
}

const std::string& BallotReceipt::getBlockHash() const noexcept {
    return m_blockHash;
}

const std::string& BallotReceipt::getReceiptCode() const noexcept {
    return m_receiptCode;
}

void BallotReceipt::displayReceipt() const {
    std::cout << "+----------------------------------------------------------------------------------------------------+\n";
    std::cout << "|                                OFFICIAL VOTER BALLOT RECEIPT                                       |\n";
    std::cout << "+----------------------------------------------------------------------------------------------------+\n";
    std::cout << "| Ballot ID     : " << std::left << std::setw(83) << m_ballotId << "|\n";
    std::cout << "| Block Index   : " << std::left << std::setw(83) << m_blockIndex << "|\n";
    std::cout << "| Block Hash    : " << std::left << std::setw(83) << m_blockHash << "|\n";
    std::cout << "| Voter Hash    : " << std::left << std::setw(83) << m_voterHash << "|\n";
    std::cout << "| Receipt Proof : " << std::left << std::setw(83) << m_receiptCode << "|\n";
    std::cout << "+----------------------------------------------------------------------------------------------------+\n";
}

