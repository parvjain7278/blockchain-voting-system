#pragma once

#include "Blockchain.h"
#include "Vote.h"
#include "Voter.h"
#include "BallotReceipt.h"
#include "Authentication.h"
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <map>
#include <stdexcept>

/**
 * @brief Custom exception for election and voting operations.
 */
class VotingException : public std::runtime_error {
public:
    explicit VotingException(const std::string& message)
        : std::runtime_error(message) {}
};

/**
 * @brief Lifecycle status of the election.
 */
enum class ElectionState {
    NOT_STARTED,
    IN_PROGRESS,
    ENDED
};

/**
 * @brief Election administration and voting orchestrator.
 * 
 * Manages voter registration, candidate rosters, ballot casting with
 * double-voting prevention, blockchain ledger integration, and
 * cryptographically audited vote tallying.
 */
class Election {
public:
    /**
     * @brief Constructs a new Election instance.
     * 
     * @param electionName Descriptive name of the election.
     * @param miningDifficulty Mining difficulty for the underlying blockchain. Defaults to 2.
     * @param electionSalt Cryptographic salt used for voter pseudonym generation.
     * @param autoStart If true, initializes state to IN_PROGRESS.
     */
    explicit Election(const std::string& electionName, 
                      uint32_t miningDifficulty = 2,
                      const std::string& electionSalt = "ELECTION_SECRET_SALT_2026",
                      bool autoStart = true);

    // Election lifecycle
    void startElection();
    void endElection();
    ElectionState getElectionState() const noexcept;
    std::string getElectionStateString() const;

    // Candidate management
    void addCandidate(const std::string& candidateName);
    void removeCandidate(const std::string& candidateName);
    bool isCandidateValid(const std::string& candidateName) const;
    const std::vector<std::string>& getCandidates() const noexcept;

    // Voter management
    void registerVoter(const std::string& voterId);
    void registerVoterWithPassword(const std::string& voterId, const std::string& password);
    bool isVoterRegistered(const std::string& voterId) const;
    const std::unordered_map<std::string, Voter>& getRegisteredVoters() const noexcept;
    const Voter* getVoter(const std::string& voterId) const;
    Voter* getVoterMutable(const std::string& voterId);

    // Authentication access
    Authentication& getAuth() noexcept;
    const Authentication& getAuth() const noexcept;

    /**
     * @brief Casts a vote in the election.
     * 
     * Validates voter registration, prevents double-voting, ensures candidate validity,
     * cryptographically signs the ballot, and records it as an immutable block in the blockchain.
     * 
     * @param voterId ID of the registered voter.
     * @param candidateName Name of the candidate being voted for.
     * @return Unique ballot ID for voter auditability.
     * @throws VotingException if validation fails or double-voting is attempted.
     */
    std::string castVote(const std::string& voterId, const std::string& candidateName);

    /**
     * @brief Casts a vote and returns an individual verification receipt for the voter.
     */
    BallotReceipt castVoteWithReceipt(const std::string& voterId, const std::string& candidateName);

    /**
     * @brief Verifies an individual ballot receipt against the blockchain ledger.
     */
    bool verifyReceipt(const BallotReceipt& receipt, std::string* outMessage = nullptr) const;

    /**
     * @brief Cryptographically audits the blockchain ledger and tallies official votes.
     * 
     * Validates all block hashes, linkages, proof-of-work, and internal ballot signatures
     * before computing official vote totals.
     * 
     * @param outAuditReport Optional pointer to store textual audit report.
     * @return Map of candidate name to total valid votes.
     * @throws VotingException if blockchain integrity is violated or tampering is detected.
     */
    std::map<std::string, uint32_t> auditAndTallyVotes(std::string* outAuditReport = nullptr) const;

    // Reporting & Display
    void displayCandidates() const;
    void displayVoterRoster() const;
    void displayElectionResults() const;

    // Ledger access
    const Blockchain& getBlockchain() const noexcept;
    Blockchain& getBlockchainMutable() noexcept;

    const std::string& getElectionName() const noexcept;
    size_t getTotalVotesCast() const noexcept;

private:
    std::string m_electionName;
    std::string m_electionSalt;
    uint32_t m_ballotCounter;

    std::vector<std::string> m_candidates;
    std::unordered_map<std::string, Voter> m_registeredVoters;
    std::unordered_set<std::string> m_castVoterHashes;

    Blockchain m_blockchain;
    ElectionState m_electionState;
    Authentication m_auth;
};

