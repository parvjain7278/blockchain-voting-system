#include "Voter.h"
#include "Crypto.h"

Voter::Voter(const std::string& voterId, const std::string& salt)
    : m_voterId(voterId),
      m_voterHash(""),
      m_hasVoted(false) {
    if (!voterId.empty()) {
        m_voterHash = generateVoterHash(voterId, salt);
        // Automatically generate a secure asymmetric key pair for the voter
        m_keyPair = Crypto::generateKeyPair(2048);
    }
}

std::string Voter::generateVoterHash(const std::string& voterId, const std::string& salt) {
    return Crypto::sha256("VOTER_SALT|" + salt + "|" + voterId);
}

const std::string& Voter::getVoterId() const noexcept {
    return m_voterId;
}

const std::string& Voter::getVoterHash() const noexcept {
    return m_voterHash;
}

bool Voter::hasVoted() const noexcept {
    return m_hasVoted;
}

void Voter::markAsVoted() {
    m_hasVoted = true;
}

const std::string& Voter::getPublicKey() const noexcept {
    return m_keyPair.publicKey;
}

const std::string& Voter::getPrivateKey() const noexcept {
    return m_keyPair.privateKey;
}

const Crypto::KeyPair& Voter::getKeyPair() const noexcept {
    return m_keyPair;
}

void Voter::setKeyPair(const Crypto::KeyPair& keyPair) {
    m_keyPair = keyPair;
}
