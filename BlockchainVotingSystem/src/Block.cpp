#include "Block.h"
#include "CryptoUtils.h"
#include <chrono>
#include <ctime>
#include <iostream>
#include <iomanip>
#include <sstream>

Block::Block(uint32_t index, const std::string& data, const std::string& previousHash)
    : m_index(index),
      m_timestamp(generateCurrentTimestamp()),
      m_data(data),
      m_previousHash(previousHash),
      m_hash(""),
      m_nonce(0) {
    m_hash = calculateHash();
}

Block::Block(uint32_t index, 
             const std::string& timestamp, 
             const std::string& data, 
             const std::string& previousHash, 
             const std::string& hash, 
             uint64_t nonce)
    : m_index(index),
      m_timestamp(timestamp),
      m_data(data),
      m_previousHash(previousHash),
      m_hash(hash),
      m_nonce(nonce) {}

std::string Block::calculateHash() const {
    std::ostringstream ss;
    ss << m_index 
       << m_timestamp 
       << m_data 
       << m_previousHash 
       << m_nonce;
    return Crypto::sha256(ss.str());
}

void Block::mineBlock(uint32_t difficulty) {
    std::string target(difficulty, '0');
    while (m_hash.substr(0, difficulty) != target) {
        ++m_nonce;
        m_hash = calculateHash();
    }
}

uint32_t Block::getIndex() const noexcept {
    return m_index;
}

const std::string& Block::getTimestamp() const noexcept {
    return m_timestamp;
}

const std::string& Block::getData() const noexcept {
    return m_data;
}

const std::string& Block::getPreviousHash() const noexcept {
    return m_previousHash;
}

const std::string& Block::getHash() const noexcept {
    return m_hash;
}

uint64_t Block::getNonce() const noexcept {
    return m_nonce;
}

void Block::setTamperedData(const std::string& newData) {
    m_data = newData;
}

void Block::setTamperedHash(const std::string& newHash) {
    m_hash = newHash;
}

void Block::displayBlock() const {
    std::cout << "+----------------------------------------------------------------------------------------------------+\n";
    std::cout << "| Block Index   : " << std::left << std::setw(83) << m_index << "|\n";
    std::cout << "| Timestamp     : " << std::left << std::setw(83) << m_timestamp << "|\n";
    std::cout << "| Nonce         : " << std::left << std::setw(83) << m_nonce << "|\n";
    std::cout << "| Data Payload  : " << std::left << std::setw(83) << m_data << "|\n";
    std::cout << "| Previous Hash : " << std::left << std::setw(83) << m_previousHash << "|\n";
    std::cout << "| Block Hash    : " << std::left << std::setw(83) << m_hash << "|\n";
    std::cout << "+----------------------------------------------------------------------------------------------------+\n";
}

std::string Block::generateCurrentTimestamp() {
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
