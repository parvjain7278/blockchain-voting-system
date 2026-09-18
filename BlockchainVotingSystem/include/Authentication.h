#pragma once

#include <string>
#include <unordered_map>
#include <chrono>
#include <stdexcept>

/**
 * @brief Exception thrown for authentication, authorization, or input validation errors.
 */
class AuthException : public std::runtime_error {
public:
    explicit AuthException(const std::string& message)
        : std::runtime_error(message) {}
};

/**
 * @brief Authenticated voter session payload.
 * 
 * Returned upon successful authentication, containing voter identity,
 * anonymous pseudonym for blockchain interaction, and a session token.
 */
struct VoterSession {
    std::string voterId;
    std::string voterHash;
    std::string sessionToken;
    std::chrono::system_clock::time_point loginTime;
};

/**
 * @brief Internal credential and security tracking record.
 */
struct AccountRecord {
    std::string username;
    std::string passwordHash; // Stored format: iterations$salt$hash
    uint32_t failedAttempts{0};
    std::chrono::system_clock::time_point lockoutUntil{};
};

/**
 * @brief Secure Authentication Subsystem for Admin and Voter operations.
 * 
 * Enforces zero-plaintext password storage, multi-iteration cryptographic salting,
 * input validation, and brute-force lockout defenses.
 */
class Authentication {
public:
    /**
     * @brief Constructs Authentication manager.
     * 
     * @param maxFailedAttempts Maximum failed attempts before account is locked out (defaults to 3).
     * @param lockoutSeconds Duration of lockout in seconds (defaults to 30).
     */
    explicit Authentication(uint32_t maxFailedAttempts = 3, uint32_t lockoutSeconds = 30);

    // Cryptographic Password Hashing & Verification
    static std::string hashPassword(const std::string& password, uint32_t iterations = 10000);
    static bool verifyPassword(const std::string& password, const std::string& storedHash);

    // Input Validation
    static bool validateUsername(const std::string& username, std::string* outError = nullptr);
    static bool validatePassword(const std::string& password, std::string* outError = nullptr);

    // Admin Operations
    void initializeAdmin(const std::string& username = "admin", 
                         const std::string& initialPassword = "AdminPassword@2026");
    bool authenticateAdmin(const std::string& username, const std::string& password);

    // Voter Operations
    void registerVoter(const std::string& voterId, 
                       const std::string& password, 
                       const std::string& salt = "ELECTION_SECRET_SALT_2026");

    VoterSession authenticateVoter(const std::string& voterId, 
                                   const std::string& password, 
                                   const std::string& salt = "ELECTION_SECRET_SALT_2026");

    bool isVoterRegistered(const std::string& voterId) const;
    bool isAccountLocked(const std::string& username) const;
    void resetLockout(const std::string& username);
    const AccountRecord* getVoterAccount(const std::string& voterId) const;
    const std::unordered_map<std::string, AccountRecord>& getVoterAccounts() const noexcept;
    void loadVoterAccount(const AccountRecord& record);

private:
    uint32_t m_maxFailedAttempts;
    uint32_t m_lockoutSeconds;

    AccountRecord m_adminAccount;
    bool m_adminInitialized;

    std::unordered_map<std::string, AccountRecord> m_voterAccounts;

    void handleFailedLogin(AccountRecord& account, const std::string& identifier);
};

