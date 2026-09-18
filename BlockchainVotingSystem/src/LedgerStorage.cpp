#include "LedgerStorage.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <vector>

void LedgerStorage::saveBlockchain(const Blockchain& chain, const std::string& filepath) {
    std::ofstream outFile(filepath, std::ios::out | std::ios::trunc);
    if (!outFile.is_open()) {
        throw BlockchainException("Failed to open file for writing: " + filepath);
    }

    outFile << "MAGIC:BLOCKCHAIN_LEDGER_V1\n";
    outFile << "DIFFICULTY:" << chain.getDifficulty() << "\n";
    outFile << "TOTAL_BLOCKS:" << chain.getChainSize() << "\n";

    for (const auto& block : chain.getChain()) {
        outFile << "BLOCK:"
                << block.getIndex() << "|"
                << block.getTimestamp() << "|"
                << block.getNonce() << "|"
                << block.getPreviousHash() << "|"
                << block.getHash() << "|"
                << block.getData() << "\n";
    }

    outFile.close();
}

Blockchain LedgerStorage::loadBlockchain(const std::string& filepath) {
    std::ifstream inFile(filepath, std::ios::in);
    if (!inFile.is_open()) {
        throw BlockchainException("Failed to open ledger file for reading: " + filepath);
    }

    std::string line;
    if (!std::getline(inFile, line) || line != "MAGIC:BLOCKCHAIN_LEDGER_V1") {
        throw BlockchainException("Invalid or unrecognized ledger file format: " + filepath);
    }

    uint32_t difficulty = 2;
    if (std::getline(inFile, line) && line.rfind("DIFFICULTY:", 0) == 0) {
        difficulty = static_cast<uint32_t>(std::stoul(line.substr(11)));
    }

    // Skip TOTAL_BLOCKS header if present
    if (std::getline(inFile, line) && line.rfind("TOTAL_BLOCKS:", 0) == 0) {
        // Read next line
    } else {
        // Line might be the first block
        inFile.seekg(0);
        std::getline(inFile, line); // MAGIC
        std::getline(inFile, line); // DIFFICULTY
    }

    std::vector<Block> loadedBlocks;

    while (std::getline(inFile, line)) {
        if (line.empty() || line.rfind("BLOCK:", 0) != 0) {
            continue;
        }

        std::string blockData = line.substr(6); // Skip "BLOCK:"
        std::stringstream ss(blockData);
        std::string token;
        std::vector<std::string> parts;

        // Extract first 5 metadata fields (index, timestamp, nonce, previousHash, hash)
        for (int i = 0; i < 5; ++i) {
            if (!std::getline(ss, token, '|')) {
                throw BlockchainException("Malformed block metadata in file: " + filepath);
            }
            parts.push_back(token);
        }

        // Remainder of line is the block's data payload
        std::string payload;
        std::getline(ss, payload);

        uint32_t index = static_cast<uint32_t>(std::stoul(parts[0]));
        std::string timestamp = parts[1];
        uint64_t nonce = static_cast<uint64_t>(std::stoull(parts[2]));
        std::string previousHash = parts[3];
        std::string hash = parts[4];

        loadedBlocks.emplace_back(index, timestamp, payload, previousHash, hash, nonce);
    }

    inFile.close();

    if (loadedBlocks.empty()) {
        throw BlockchainException("Ledger file contains no blocks: " + filepath);
    }

    Blockchain chain(difficulty);
    chain.loadBlocks(loadedBlocks);

    // Cryptographically verify the loaded chain immediately
    std::string validationError;
    if (!chain.isChainValid(&validationError)) {
        throw BlockchainException("Tampering detected in persistent ledger file! " + validationError);
    }

    return chain;
}

void LedgerStorage::exportLedgerToJSON(const Blockchain& chain, const std::string& filepath) {
    std::ofstream outFile(filepath, std::ios::out | std::ios::trunc);
    if (!outFile.is_open()) {
        throw BlockchainException("Failed to open JSON export file: " + filepath);
    }

    outFile << "{\n";
    outFile << "  \"blockchain\": {\n";
    outFile << "    \"difficulty\": " << chain.getDifficulty() << ",\n";
    outFile << "    \"totalBlocks\": " << chain.getChainSize() << ",\n";
    outFile << "    \"blocks\": [\n";

    const auto& blocks = chain.getChain();
    for (size_t i = 0; i < blocks.size(); ++i) {
        const auto& b = blocks[i];
        outFile << "      {\n";
        outFile << "        \"index\": " << b.getIndex() << ",\n";
        outFile << "        \"timestamp\": \"" << b.getTimestamp() << "\",\n";
        outFile << "        \"nonce\": " << b.getNonce() << ",\n";
        outFile << "        \"previousHash\": \"" << b.getPreviousHash() << "\",\n";
        outFile << "        \"hash\": \"" << b.getHash() << "\",\n";
        
        // Escape quotes in payload if any
        std::string escapedData;
        for (char c : b.getData()) {
            if (c == '"') escapedData += "\\\"";
            else if (c == '\\') escapedData += "\\\\";
            else escapedData += c;
        }
        outFile << "        \"data\": \"" << escapedData << "\"\n";
        outFile << "      }" << (i + 1 < blocks.size() ? "," : "") << "\n";
    }

    outFile << "    ]\n";
    outFile << "  }\n";
    outFile << "}\n";

    outFile.close();
}

