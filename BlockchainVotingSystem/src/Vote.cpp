#include "Vote.h"
#include "Crypto.h"
#include <chrono>
#include <ctime>
#include <sstream>
#include <vector>
#include <stdexcept>

Vote::Vote(const std::string& ballotId, 
           const std::string& voterHash, 
           const std::string& candidate, 
           const std::string& timestamp)
    : m_ballotId(ballotId),
      m_voterHash(voterHash),
      m_candidate(candidate),
      m_timestamp(timestamp.empty() ? generateCurrentTimestamp() : timestamp),
      m_publicKey(""),
      m_signature("") {
    m_signature = computeHashSignature();
}

Vote::Vote(const std::string& ballotId, 
           const std::string& voterHash, 
           const std::string& candidate, 
           const std::string& timestamp,
           const std::string& publicKey,
           const std::string& signature)
    : m_ballotId(ballotId),
      m_voterHash(voterHash),
      m_candidate(candidate),
      m_timestamp(timestamp.empty() ? generateCurrentTimestamp() : timestamp),
      m_publicKey(publicKey),
      m_signature(signature) {}

std::string Vote::getPayloadToSign() const {
    std::ostringstream ss;
    ss << m_ballotId << ":" 
       << m_voterHash << ":" 
       << m_candidate << ":" 
       << m_timestamp;
    return ss.str();
}

void Vote::sign(const std::string& privateKeyHex) {
    m_signature = Crypto::signTransaction(getPayloadToSign(), privateKeyHex);
}

bool Vote::verifySignature(const std::string& publicKeyHex) const {
    const std::string& key = publicKeyHex.empty() ? m_publicKey : publicKeyHex;
    if (key.empty() || m_signature.empty()) {
        return false;
    }
    return Crypto::verifySignature(getPayloadToSign(), m_signature, key);
}

std::string Vote::computeHashSignature() const {
    return Crypto::sha256(getPayloadToSign());
}

std::string Vote::serialize() const {
    std::ostringstream ss;
    ss << "VOTE_TX|" 
       << m_ballotId << "|" 
       << m_voterHash << "|" 
       << m_candidate << "|" 
       << m_timestamp << "|";
    if (!m_publicKey.empty()) {
        ss << m_publicKey << "|" 
           << m_signature;
    } else {
        ss << m_signature;
    }
    return ss.str();
}

bool Vote::isVotePayload(const std::string& raw) {
    return raw.rfind("VOTE_TX|", 0) == 0;
}

Vote Vote::deserialize(const std::string& raw) {
    if (!isVotePayload(raw)) {
        throw std::invalid_argument("Payload is not a valid Vote transaction format.");
    }

    std::vector<std::string> tokens;
    std::stringstream ss(raw);
    std::string item;
    while (std::getline(ss, item, '|')) {
        tokens.push_back(item);
    }

    if (tokens.size() == 7) {
        // [0]="VOTE_TX", [1]=ballotId, [2]=voterHash, [3]=candidate, [4]=timestamp, [5]=publicKey, [6]=signature
        Vote vote(tokens[1], tokens[2], tokens[3], tokens[4], tokens[5], tokens[6]);
        if (!vote.isValid()) {
            throw std::runtime_error("Deserialized vote fails cryptographic signature check.");
        }
        return vote;
    } else if (tokens.size() == 6) {
        // Legacy format: [0]="VOTE_TX", [1]=ballotId, [2]=voterHash, [3]=candidate, [4]=timestamp, [5]=signature
        Vote vote(tokens[1], tokens[2], tokens[3], tokens[4]);
        vote.m_signature = tokens[5];
        if (!vote.isValid()) {
            throw std::runtime_error("Deserialized vote fails cryptographic signature check.");
        }
        return vote;
    } else {
        throw std::invalid_argument("Malformed vote transaction: unexpected token count (" 
                                    + std::to_string(tokens.size()) + ").");
    }
}

bool Vote::isValid() const {
    if (!m_publicKey.empty()) {
        return verifySignature(m_publicKey);
    }
    return m_signature == computeHashSignature();
}

const std::string& Vote::getBallotId() const noexcept {
    return m_ballotId;
}

const std::string& Vote::getVoterHash() const noexcept {
    return m_voterHash;
}

const std::string& Vote::getCandidate() const noexcept {
    return m_candidate;
}

const std::string& Vote::getTimestamp() const noexcept {
    return m_timestamp;
}

const std::string& Vote::getPublicKey() const noexcept {
    return m_publicKey;
}

const std::string& Vote::getSignature() const noexcept {
    return m_signature;
}

void Vote::setPublicKey(const std::string& publicKey) {
    m_publicKey = publicKey;
}

void Vote::setSignature(const std::string& signature) {
    m_signature = signature;
}

std::string Vote::generateCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    std::time_t timeNow = std::chrono::system_clock::to_time_t(now);
    std::tm* gmt = std::gmtime(&timeNow);
    char buffer[64];
    if (gmt != nullptr) {
        std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S UTC", gmt);
    } else {
        std::snprintf(buffer, sizeof(buffer), "%ld", static_cast<long>(timeNow));
    }
    return std::string(buffer);
}
