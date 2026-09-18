#include "Election.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <algorithm>

Election::Election(const std::string& electionName, 
                   uint32_t miningDifficulty,
                   const std::string& electionSalt,
                   bool autoStart)
    : m_electionName(electionName),
      m_electionSalt(electionSalt),
      m_ballotCounter(1000),
      m_blockchain(miningDifficulty),
      m_electionState(autoStart ? ElectionState::IN_PROGRESS : ElectionState::NOT_STARTED) {}

void Election::startElection() {
    if (m_candidates.empty()) {
        throw VotingException("Cannot start election: No candidates have been registered.");
    }
    if (m_electionState == ElectionState::IN_PROGRESS) {
        throw VotingException("Election is already in progress.");
    }
    if (m_electionState == ElectionState::ENDED) {
        throw VotingException("Cannot restart an election that has already concluded.");
    }
    m_electionState = ElectionState::IN_PROGRESS;
}

void Election::endElection() {
    if (m_electionState != ElectionState::IN_PROGRESS) {
        throw VotingException("Cannot end election: Election is not currently in progress.");
    }
    m_electionState = ElectionState::ENDED;
}

ElectionState Election::getElectionState() const noexcept {
    return m_electionState;
}

std::string Election::getElectionStateString() const {
    switch (m_electionState) {
        case ElectionState::NOT_STARTED: return "NOT_STARTED";
        case ElectionState::IN_PROGRESS: return "IN_PROGRESS (ACTIVE)";
        case ElectionState::ENDED: return "ENDED (CONCLUDED)";
    }
    return "UNKNOWN";
}

void Election::addCandidate(const std::string& candidateName) {
    if (candidateName.empty()) {
        throw VotingException("Candidate name cannot be empty.");
    }
    if (isCandidateValid(candidateName)) {
        throw VotingException("Candidate '" + candidateName + "' is already registered.");
    }
    m_candidates.push_back(candidateName);
}

void Election::removeCandidate(const std::string& candidateName) {
    if (m_electionState == ElectionState::IN_PROGRESS) {
        throw VotingException("Cannot remove candidate while election is actively in progress.");
    }
    auto it = std::find(m_candidates.begin(), m_candidates.end(), candidateName);
    if (it == m_candidates.end()) {
        throw VotingException("Candidate '" + candidateName + "' not found on roster.");
    }
    m_candidates.erase(it);
}

bool Election::isCandidateValid(const std::string& candidateName) const {
    return std::find(m_candidates.begin(), m_candidates.end(), candidateName) != m_candidates.end();
}

const std::vector<std::string>& Election::getCandidates() const noexcept {
    return m_candidates;
}

void Election::registerVoter(const std::string& voterId) {
    if (voterId.empty()) {
        throw VotingException("Voter ID cannot be empty.");
    }
    if (isVoterRegistered(voterId)) {
        throw VotingException("Voter ID '" + voterId + "' is already registered.");
    }
    m_registeredVoters.emplace(voterId, Voter(voterId, m_electionSalt));
}

void Election::registerVoterWithPassword(const std::string& voterId, const std::string& password) {
    m_auth.registerVoter(voterId, password, m_electionSalt);
    registerVoter(voterId);
}

Authentication& Election::getAuth() noexcept {
    return m_auth;
}

const Authentication& Election::getAuth() const noexcept {
    return m_auth;
}

bool Election::isVoterRegistered(const std::string& voterId) const {
    return m_registeredVoters.find(voterId) != m_registeredVoters.end();
}

const std::unordered_map<std::string, Voter>& Election::getRegisteredVoters() const noexcept {
    return m_registeredVoters;
}

const Voter* Election::getVoter(const std::string& voterId) const {
    auto it = m_registeredVoters.find(voterId);
    if (it != m_registeredVoters.end()) {
        return &it->second;
    }
    return nullptr;
}

Voter* Election::getVoterMutable(const std::string& voterId) {
    auto it = m_registeredVoters.find(voterId);
    if (it != m_registeredVoters.end()) {
        return &it->second;
    }
    return nullptr;
}

std::string Election::castVote(const std::string& voterId, const std::string& candidateName) {
    // 0. Verify election lifecycle state
    if (m_electionState == ElectionState::NOT_STARTED) {
        throw VotingException("Voting denied: Election has not started yet.");
    }
    if (m_electionState == ElectionState::ENDED) {
        throw VotingException("Voting denied: Election has already ended.");
    }

    // 1. Verify voter registration
    auto it = m_registeredVoters.find(voterId);
    if (it == m_registeredVoters.end()) {
        throw VotingException("Voting denied: Voter ID '" + voterId + "' is not registered.");
    }

    // 2. Prevent double-voting via voter record
    if (it->second.hasVoted()) {
        throw VotingException("Double-voting denied! Voter ID '" + voterId + "' has already cast a ballot.");
    }

    // 3. Prevent double-voting via pseudonymous voter hash
    const std::string& voterHash = it->second.getVoterHash();
    if (m_castVoterHashes.find(voterHash) != m_castVoterHashes.end()) {
        throw VotingException("Double-voting denied! Pseudonymous voter hash has already been recorded.");
    }

    // 4. Verify candidate validity
    if (!isCandidateValid(candidateName)) {
        throw VotingException("Voting denied: Candidate '" + candidateName + "' is not on the ballot.");
    }

    // Transaction Flow:
    // 1. Create Vote
    std::string ballotId = "BLT-" + std::to_string(++m_ballotCounter);
    Vote vote(ballotId, voterHash, candidateName);

    // 2. Serialize Transaction
    std::string txPayload = vote.getPayloadToSign();

    // 3. Sign Transaction using voter's protected private key
    std::string signature = Crypto::signTransaction(txPayload, it->second.getPrivateKey());
    vote.setSignature(signature);
    vote.setPublicKey(it->second.getPublicKey());

    // 4. Verify Signature before accepting the transaction
    if (!Crypto::verifySignature(txPayload, signature, it->second.getPublicKey())) {
        throw VotingException("Voting denied: Transaction digital signature failed verification.");
    }

    // 5. Add to Blockchain
    m_blockchain.addBlock(vote.serialize());

    // 6. Update voting state
    it->second.markAsVoted();
    m_castVoterHashes.insert(voterHash);

    return ballotId;
}

BallotReceipt Election::castVoteWithReceipt(const std::string& voterId, const std::string& candidateName) {
    // 0. Verify election lifecycle state
    if (m_electionState == ElectionState::NOT_STARTED) {
        throw VotingException("Voting denied: Election has not started yet.");
    }
    if (m_electionState == ElectionState::ENDED) {
        throw VotingException("Voting denied: Election has already ended.");
    }

    // 1. Verify voter registration
    auto it = m_registeredVoters.find(voterId);
    if (it == m_registeredVoters.end()) {
        throw VotingException("Voting denied: Voter ID '" + voterId + "' is not registered.");
    }

    // 2. Prevent double-voting via voter record
    if (it->second.hasVoted()) {
        throw VotingException("Double-voting denied! Voter ID '" + voterId + "' has already cast a ballot.");
    }

    // 3. Prevent double-voting via pseudonymous voter hash
    const std::string& voterHash = it->second.getVoterHash();
    if (m_castVoterHashes.find(voterHash) != m_castVoterHashes.end()) {
        throw VotingException("Double-voting denied! Pseudonymous voter hash has already been recorded.");
    }

    // 4. Verify candidate validity
    if (!isCandidateValid(candidateName)) {
        throw VotingException("Voting denied: Candidate '" + candidateName + "' is not on the ballot.");
    }

    // Transaction Flow:
    // 1. Create Vote
    std::string ballotId = "BLT-" + std::to_string(++m_ballotCounter);
    Vote vote(ballotId, voterHash, candidateName);

    // 2. Serialize Transaction
    std::string txPayload = vote.getPayloadToSign();

    // 3. Sign Transaction using voter's protected private key
    std::string signature = Crypto::signTransaction(txPayload, it->second.getPrivateKey());
    vote.setSignature(signature);
    vote.setPublicKey(it->second.getPublicKey());

    // 4. Verify Signature before accepting the transaction
    if (!Crypto::verifySignature(txPayload, signature, it->second.getPublicKey())) {
        throw VotingException("Voting denied: Transaction digital signature failed verification.");
    }

    // 5. Add to Blockchain
    m_blockchain.addBlock(vote.serialize());

    // 6. Update voting state
    it->second.markAsVoted();
    m_castVoterHashes.insert(voterHash);

    uint32_t blockIndex = static_cast<uint32_t>(m_blockchain.getChainSize() - 1);
    const std::string& blockHash = m_blockchain.getLatestBlock().getHash();

    return BallotReceipt(ballotId, voterHash, blockIndex, blockHash);
}

bool Election::verifyReceipt(const BallotReceipt& receipt, std::string* outMessage) const {
    return receipt.verifyOnChain(m_blockchain, outMessage);
}

std::map<std::string, uint32_t> Election::auditAndTallyVotes(std::string* outAuditReport) const {
    std::ostringstream auditLog;
    auditLog << "--- BLOCKCHAIN ELECTION AUDIT REPORT ---\n";
    auditLog << "Election Name: " << m_electionName << "\n";

    // 1. Cryptographic ledger integrity check
    std::string chainError;
    if (!m_blockchain.isChainValid(&chainError)) {
        auditLog << "[CRITICAL FAILURE] Blockchain verification failed: " << chainError << "\n";
        if (outAuditReport) *outAuditReport = auditLog.str();
        throw VotingException("Audit rejected: Blockchain integrity compromised! " + chainError);
    }
    auditLog << "[PASS] Blockchain cryptographic hashes, parent links, and proof-of-work are intact.\n";

    // 2. Initialize tally map
    std::map<std::string, uint32_t> tally;
    for (const auto& candidate : m_candidates) {
        tally[candidate] = 0;
    }

    // 3. Scan ledger blocks (Block 0 is Genesis Block)
    const auto& chain = m_blockchain.getChain();
    std::unordered_set<std::string> auditedVoterHashes;
    uint32_t validVotes = 0;

    for (size_t i = 1; i < chain.size(); ++i) {
        const Block& block = chain[i];
        if (!Vote::isVotePayload(block.getData())) {
            auditLog << "[WARN] Block #" << block.getIndex() << " contains non-vote data. Skipped.\n";
            continue;
        }

        Vote vote = Vote::deserialize(block.getData());

        // Verify ballot internal signature
        if (!vote.isValid()) {
            auditLog << "[CRITICAL FAILURE] Corrupted ballot signature at Block #" << block.getIndex() << "\n";
            if (outAuditReport) *outAuditReport = auditLog.str();
            throw VotingException("Audit rejected: Corrupted ballot signature at Block #" + std::to_string(block.getIndex()));
        }

        // Verify no on-chain double voting
        if (auditedVoterHashes.find(vote.getVoterHash()) != auditedVoterHashes.end()) {
            auditLog << "[CRITICAL FAILURE] Duplicate voter hash found on ledger at Block #" << block.getIndex() << "\n";
            if (outAuditReport) *outAuditReport = auditLog.str();
            throw VotingException("Audit rejected: Duplicate voter hash detected at Block #" + std::to_string(block.getIndex()));
        }

        auditedVoterHashes.insert(vote.getVoterHash());
        tally[vote.getCandidate()]++;
        ++validVotes;
    }

    auditLog << "[PASS] All " << validVotes << " ballots cryptographically verified and tallied without error.\n";
    if (outAuditReport) *outAuditReport = auditLog.str();

    return tally;
}

void Election::displayCandidates() const {
    std::cout << "\n+-------------------------------------------------------------+\n";
    std::cout << "|                   OFFICIAL CANDIDATE LIST                   |\n";
    std::cout << "+-----+-------------------------------------------------------+\n";
    std::cout << "| No. | Candidate Name                                        |\n";
    std::cout << "+-----+-------------------------------------------------------+\n";
    for (size_t i = 0; i < m_candidates.size(); ++i) {
        std::cout << "| " << std::setw(3) << (i + 1) << " | " 
                  << std::left << std::setw(53) << m_candidates[i] << " |\n";
    }
    std::cout << "+-----+-------------------------------------------------------+\n";
}

void Election::displayVoterRoster() const {
    std::cout << "\n+------------------------------------------------------------------------------------------------------+\n";
    std::cout << "|                                     REGISTERED VOTER ROSTER                                          |\n";
    std::cout << "+---------------+-------------------------------------------------------------------+------------------+\n";
    std::cout << "| Voter ID      | Cryptographic Voter Pseudonym (SHA-256)                           | Ballot Status    |\n";
    std::cout << "+---------------+-------------------------------------------------------------------+------------------+\n";
    for (const auto& pair : m_registeredVoters) {
        std::string status = pair.second.hasVoted() ? "VOTED" : "ELIGIBLE";
        std::cout << "| " << std::left << std::setw(13) << pair.first << " | "
                  << std::left << std::setw(65) << pair.second.getVoterHash() << " | "
                  << std::left << std::setw(16) << status << " |\n";
    }
    std::cout << "+---------------+-------------------------------------------------------------------+------------------+\n";
}

void Election::displayElectionResults() const {
    std::string auditReport;
    std::map<std::string, uint32_t> results = auditAndTallyVotes(&auditReport);

    uint32_t totalVotes = 0;
    for (const auto& pair : results) {
        totalVotes += pair.second;
    }

    std::cout << "\n====================================================================================================\n";
    std::cout << "                                   OFFICIAL ELECTION RESULTS                                        \n";
    std::cout << " Election: " << m_electionName << "\n";
    std::cout << " Total Registered Voters: " << m_registeredVoters.size() 
              << " | Total Votes Cast: " << totalVotes;
    if (!m_registeredVoters.empty()) {
        double turnout = (static_cast<double>(totalVotes) / m_registeredVoters.size()) * 100.0;
        std::cout << " | Voter Turnout: " << std::fixed << std::setprecision(1) << turnout << "%\n";
    } else {
        std::cout << "\n";
    }
    std::cout << "====================================================================================================\n";

    std::cout << "+-----+-------------------------------------------------------+-------------+-----------------------+\n";
    std::cout << "| No. | Candidate Name                                        | Total Votes | Percentage            |\n";
    std::cout << "+-----+-------------------------------------------------------+-------------+-----------------------+\n";

    uint32_t maxVotes = 0;
    std::string winner = "None";
    bool tie = false;

    size_t idx = 1;
    for (const auto& pair : results) {
        double pct = totalVotes > 0 ? (static_cast<double>(pair.second) / totalVotes) * 100.0 : 0.0;
        std::cout << "| " << std::setw(3) << idx++ << " | "
                  << std::left << std::setw(53) << pair.first << " | "
                  << std::right << std::setw(11) << pair.second << " | "
                  << std::fixed << std::setprecision(2) << std::setw(20) << pct << "% |\n";

        if (pair.second > maxVotes) {
            maxVotes = pair.second;
            winner = pair.first;
            tie = false;
        } else if (pair.second == maxVotes && maxVotes > 0) {
            tie = true;
        }
    }
    std::cout << "+-----+-------------------------------------------------------+-------------+-----------------------+\n";

    if (totalVotes == 0) {
        std::cout << "\n [RESULT] No votes have been cast yet.\n";
    } else if (tie) {
        std::cout << "\n [RESULT] The election resulted in a TIE with " << maxVotes << " votes.\n";
    } else {
        std::cout << "\n [WINNER] " << winner << " wins the election with " << maxVotes << " votes!\n";
    }
    std::cout << "====================================================================================================\n\n";
}

const Blockchain& Election::getBlockchain() const noexcept {
    return m_blockchain;
}

Blockchain& Election::getBlockchainMutable() noexcept {
    return m_blockchain;
}

const std::string& Election::getElectionName() const noexcept {
    return m_electionName;
}

size_t Election::getTotalVotesCast() const noexcept {
    return m_castVoterHashes.size();
}

