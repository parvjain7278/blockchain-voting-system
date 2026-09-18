#pragma once

#include "Blockchain.h"
#include <string>

/**
 * @brief Handles persistent disk I/O and on-load cryptographic verification of ledgers.
 * 
 * Provides secure saving, loading with automatic tamper detection, and JSON export.
 */
class LedgerStorage {
public:
    /**
     * @brief Saves the active blockchain ledger to disk.
     * 
     * @param chain Blockchain instance to persist.
     * @param filepath Destination file path (e.g. "data/blockchain_ledger.dat").
     */
    static void saveBlockchain(const Blockchain& chain, const std::string& filepath);

    /**
     * @brief Loads the blockchain ledger from disk and cryptographically verifies integrity.
     * 
     * Every block hash, linkage pointer, and difficulty constraint is verified.
     * If the file was edited or tampered with on disk, an exception is thrown.
     * 
     * @param filepath Source file path.
     * @return Reconstructed and verified Blockchain.
     * @throws BlockchainException if file is missing, malformed, or tampered.
     */
    static Blockchain loadBlockchain(const std::string& filepath);

    /**
     * @brief Exports the entire blockchain into formatted JSON for external auditing.
     * 
     * @param chain Blockchain instance to export.
     * @param filepath Destination JSON file path (e.g. "data/blockchain_ledger.json").
     */
    static void exportLedgerToJSON(const Blockchain& chain, const std::string& filepath);
};

