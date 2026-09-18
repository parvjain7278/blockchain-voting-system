#include "Authentication.h"
#include "CryptoUtils.h"
#include "Voter.h"
#include <sstream>
#include <vector>
#include <cctype>

Authentication::Authentication(uint32_t maxFailedAttempts, uint32_t lockoutSeconds)
    : m_maxFailedAttempts(maxFailedAttempts),
      m_lockoutSeconds(lockoutSeconds),
      m_adminInitialized(false) {
    // Initialize default admin
    initializeAdmin();
}

void Authentication::initializeAdmin(const std::string& username, const std::string& initialPassword) {
    std::string userErr, passErr;
    if (!validateUsername(username, &userErr)) {
        throw AuthException("Admin initialization failed: " + userErr);
    }
    if (!validatePassword(initialPassword, &passErr)) {
        throw AuthException("Admin initialization failed: " + passErr);
    }

    m_adminAccount.username = username;
    m_adminAccount.passwordHash = hashPassword(initialPassword);
    m_adminAccount.failedAttempts = 0;
    m_adminAccount.lockoutUntil = std::chrono::system_clock::time_point{};
    m_adminInitialized = true;
}

std::string Authentication::hashPassword(const std::string& password, uint32_t iterations) {
    std::string err;
    if (!validatePassword(password, &err)) {
        throw AuthException("Password hashing error: " + err);
    }

    // Generate 16-byte (32-char hex) CSPRNG random salt
    std::string salt = Crypto::generateRandomHexSalt(16);

    // Multi-iteration cryptographic stretching
    std::string current = Crypto::sha256("PWD_SALT|" + salt + "|" + password);
    for (uint32_t i = 1; i < iterations; ++i) {
        current = Crypto::sha256(current + "|" + salt);
    }

    // Format: iterations$salt$hash
    return std::to_string(iterations) + "$" + salt + "$" + current;
}

bool Authentication::verifyPassword(const std::string& password, const std::string& storedHash) {
    std::stringstream ss(storedHash);
    std::string token;
    std::vector<std::string> parts;
    while (std::getline(ss, token, '$')) {
        parts.push_back(token);
    }

    if (parts.size() != 3) {
        return false;
    }

    uint32_t iterations = 0;
    try {
        iterations = static_cast<uint32_t>(std::stoul(parts[0]));
    } catch (...) {
        return false;
    }

    const std::string& salt = parts[1];
    const std::string& expectedHash = parts[2];

    // Recompute stretched hash with same salt and iterations
    std::string current = Crypto::sha256("PWD_SALT|" + salt + "|" + password);
    for (uint32_t i = 1; i < iterations; ++i) {
        current = Crypto::sha256(current + "|" + salt);
    }

    // Constant-time side-channel resistant equality check
    return Crypto::constantTimeEquals(current, expectedHash);
}

bool Authentication::validateUsername(const std::string& username, std::string* outError) {
    if (username.empty()) {
        if (outError) *outError = "Username/ID cannot be empty.";
        return false;
    }
    if (username.size() < 3 || username.size() > 32) {
        if (outError) *outError = "Username/ID must be between 3 and 32 characters.";
        return false;
    }
    for (char c : username) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_' && c != '-') {
            if (outError) *outError = "Username/ID can only contain alphanumeric characters, underscores, and hyphens.";
            return false;
        }
    }
    return true;
}

bool Authentication::validatePassword(const std::string& password, std::string* outError) {
    if (password.empty()) {
        if (outError) *outError = "Password cannot be empty.";
        return false;
    }
    if (password.size() < 6) {
        if (outError) *outError = "Password must be at least 6 characters long.";
        return false;
    }
    if (password.size() > 128) {
        if (outError) *outError = "Password cannot exceed 128 characters.";
        return false;
    }
    return true;
}

void Authentication::handleFailedLogin(AccountRecord& account, const std::string& identifier) {
    ++account.failedAttempts;
    if (account.failedAttempts >= m_maxFailedAttempts) {
        account.lockoutUntil = std::chrono::system_clock::now() + std::chrono::seconds(m_lockoutSeconds);
        throw AuthException("Account '" + identifier + "' has been temporarily locked due to " 
                            + std::to_string(account.failedAttempts) + " failed login attempts. Please wait " 
                            + std::to_string(m_lockoutSeconds) + " seconds.");
    }

    uint32_t remaining = m_maxFailedAttempts - account.failedAttempts;
    throw AuthException("Invalid credentials for '" + identifier + "'. " 
                        + std::to_string(remaining) + " attempt(s) remaining.");
}

bool Authentication::authenticateAdmin(const std::string& username, const std::string& password) {
    if (!m_adminInitialized) {
        throw AuthException("Admin account is not initialized.");
    }

    // Check account lockout
    auto now = std::chrono::system_clock::now();
    if (now < m_adminAccount.lockoutUntil) {
        auto remainingSecs = std::chrono::duration_cast<std::chrono::seconds>(m_adminAccount.lockoutUntil - now).count();
        throw AuthException("Admin account is temporarily locked. Please wait " 
                            + std::to_string(remainingSecs + 1) + " seconds.");
    }

    // Validate username match
    if (username != m_adminAccount.username) {
        handleFailedLogin(m_adminAccount, username);
        return false;
    }

    // Verify password hash
    if (!verifyPassword(password, m_adminAccount.passwordHash)) {
        handleFailedLogin(m_adminAccount, username);
        return false;
    }

    // Reset failed counter on successful authentication
    m_adminAccount.failedAttempts = 0;
    return true;
}

void Authentication::registerVoter(const std::string& voterId, 
                                  const std::string& password, 
                                  const std::string& /* salt */) {
    std::string userErr, passErr;
    if (!validateUsername(voterId, &userErr)) {
        throw AuthException("Registration rejected: " + userErr);
    }
    if (!validatePassword(password, &passErr)) {
        throw AuthException("Registration rejected: " + passErr);
    }

    if (isVoterRegistered(voterId)) {
        throw AuthException("Registration rejected: Voter ID '" + voterId + "' is already registered.");
    }

    AccountRecord record;
    record.username = voterId;
    record.passwordHash = hashPassword(password);
    record.failedAttempts = 0;
    record.lockoutUntil = std::chrono::system_clock::time_point{};

    m_voterAccounts.emplace(voterId, std::move(record));
}

VoterSession Authentication::authenticateVoter(const std::string& voterId, 
                                               const std::string& password, 
                                               const std::string& salt) {
    auto it = m_voterAccounts.find(voterId);
    if (it == m_voterAccounts.end()) {
        throw AuthException("Authentication failed: Voter ID '" + voterId + "' not found.");
    }

    AccountRecord& account = it->second;

    // Check lockout
    auto now = std::chrono::system_clock::now();
    if (now < account.lockoutUntil) {
        auto remainingSecs = std::chrono::duration_cast<std::chrono::seconds>(account.lockoutUntil - now).count();
        throw AuthException("Voter account is temporarily locked. Please wait " 
                            + std::to_string(remainingSecs + 1) + " seconds.");
    }

    // Verify password
    if (!verifyPassword(password, account.passwordHash)) {
        handleFailedLogin(account, voterId);
    }

    // Success: reset failed attempts
    account.failedAttempts = 0;

    // Generate authenticated session
    VoterSession session;
    session.voterId = voterId;
    session.voterHash = Voter::generateVoterHash(voterId, salt);
    session.loginTime = now;
    
    // Generate secure session token
    std::string timeStr = std::to_string(std::chrono::system_clock::to_time_t(now));
    session.sessionToken = Crypto::sha256("TOKEN|" + voterId + "|" + timeStr + "|" + Crypto::generateRandomHexSalt(8));

    return session;
}

bool Authentication::isVoterRegistered(const std::string& voterId) const {
    return m_voterAccounts.find(voterId) != m_voterAccounts.end();
}

bool Authentication::isAccountLocked(const std::string& username) const {
    auto now = std::chrono::system_clock::now();
    if (username == m_adminAccount.username) {
        return now < m_adminAccount.lockoutUntil;
    }
    auto it = m_voterAccounts.find(username);
    if (it != m_voterAccounts.end()) {
        return now < it->second.lockoutUntil;
    }
    return false;
}

void Authentication::resetLockout(const std::string& username) {
    if (username == m_adminAccount.username) {
        m_adminAccount.failedAttempts = 0;
        m_adminAccount.lockoutUntil = std::chrono::system_clock::time_point{};
        return;
    }
    auto it = m_voterAccounts.find(username);
    if (it != m_voterAccounts.end()) {
        it->second.failedAttempts = 0;
        it->second.lockoutUntil = std::chrono::system_clock::time_point{};
    }
}

const AccountRecord* Authentication::getVoterAccount(const std::string& voterId) const {
    auto it = m_voterAccounts.find(voterId);
    if (it != m_voterAccounts.end()) {
        return &it->second;
    }
    return nullptr;
}

const std::unordered_map<std::string, AccountRecord>& Authentication::getVoterAccounts() const noexcept {
    return m_voterAccounts;
}

void Authentication::loadVoterAccount(const AccountRecord& record) {
    m_voterAccounts[record.username] = record;
}

