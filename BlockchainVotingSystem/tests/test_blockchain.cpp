#include "Blockchain.h"
#include "CryptoUtils.h"
#include "Vote.h"
#include "Voter.h"
#include "Election.h"
#include "BallotReceipt.h"
#include "LedgerStorage.h"
#include "Authentication.h"
#include <iostream>
#include <fstream>
#include <cassert>

void testSHA256StandardVectors() {
    std::cout << "[TEST 1/17] Running SHA-256 standard test vectors...\n";
    std::string emptyHash = Crypto::sha256("");
    assert(emptyHash == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    std::string helloHash = Crypto::sha256("hello");
    assert(helloHash == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    std::cout << "            -> PASSED: Cryptographic library matches NIST standards.\n";
}

void testGenesisBlock() {
    std::cout << "[TEST 2/17] Running Genesis Block creation test...\n";
    Blockchain chain(1);
    assert(chain.getChainSize() == 1);
    const Block& genesis = chain.getLatestBlock();
    assert(genesis.getIndex() == 0);
    assert(genesis.getHash() == genesis.calculateHash());
    assert(chain.isChainValid());
    std::cout << "            -> PASSED: Genesis Block created and validated.\n";
}

void testAddAndLinkBlocks() {
    std::cout << "[TEST 3/17] Running Block addition and hash linking test...\n";
    Blockchain chain(1);
    chain.addBlock("Vote #1 - Candidate A");
    chain.addBlock("Vote #2 - Candidate B");
    chain.addBlock("Vote #3 - Candidate C");

    assert(chain.getChainSize() == 4);
    assert(chain.isChainValid());

    const auto& blocks = chain.getChain();
    for (size_t i = 1; i < blocks.size(); ++i) {
        assert(blocks[i].getPreviousHash() == blocks[i - 1].getHash());
        assert(blocks[i].getHash() == blocks[i].calculateHash());
    }
    std::cout << "            -> PASSED: Blocks linked with valid SHA-256 pointers.\n";
}

void testTamperDetection() {
    std::cout << "[TEST 4/17] Running Tamper Resistance and Detection test...\n";
    Blockchain chain(1);
    chain.addBlock("Vote #1 - Candidate A");
    chain.addBlock("Vote #2 - Candidate B");
    assert(chain.isChainValid());

    // Modify block 1 data
    chain.getBlockMutable(1).setTamperedData("Vote #1 - FRAUDULENT Candidate X");
    std::string err;
    bool valid = chain.isChainValid(&err);
    assert(!valid);
    assert(!err.empty());
    std::cout << "            -> PASSED: Tampering correctly caught.\n";
}

void testVoteSerializationAndSignature() {
    std::cout << "[TEST 5/17] Running Vote serialization and cryptographic signature test...\n";
    Vote vote("BLT-9999", "voter_hash_123", "Alice Johnson", "2026-09-14 12:00:00 UTC");
    assert(vote.isValid());

    std::string serialized = vote.serialize();
    assert(Vote::isVotePayload(serialized));

    Vote reconstructed = Vote::deserialize(serialized);
    assert(reconstructed.getBallotId() == "BLT-9999");
    assert(reconstructed.getVoterHash() == "voter_hash_123");
    assert(reconstructed.getCandidate() == "Alice Johnson");
    assert(reconstructed.isValid());
    std::cout << "            -> PASSED: Vote serialization and signature verified.\n";
}

void testElectionVotingAndDoubleVoting() {
    std::cout << "[TEST 6/17] Running Election voting and double-voting prevention test...\n";
    Election election("Campus Election 2026", 1);
    election.addCandidate("Alice");
    election.addCandidate("Bob");

    election.registerVoter("VTR-100");
    election.registerVoter("VTR-200");

    // Valid votes
    std::string b1 = election.castVote("VTR-100", "Alice");
    assert(!b1.empty());
    assert(election.getTotalVotesCast() == 1);

    // Double voting attempt by VTR-100
    bool doubleVoteBlocked = false;
    try {
        election.castVote("VTR-100", "Bob");
    } catch (const VotingException&) {
        doubleVoteBlocked = true;
    }
    assert(doubleVoteBlocked);
    assert(election.getTotalVotesCast() == 1);
    std::cout << "            -> PASSED: Double-voting attempt blocked.\n";
}

void testUnregisteredVoter() {
    std::cout << "[TEST 7/17] Running Unregistered voter rejection test...\n";
    Election election("City Council 2026", 1);
    election.addCandidate("Alice");

    bool blocked = false;
    try {
        election.castVote("ILLEGAL_VOTER", "Alice");
    } catch (const VotingException&) {
        blocked = true;
    }
    assert(blocked);
    std::cout << "            -> PASSED: Unregistered voter successfully rejected.\n";
}

void testElectionAuditAndTally() {
    std::cout << "[TEST 8/17] Running Election Audit & Vote Tallying test...\n";
    Election election("National Student President", 1);
    election.addCandidate("Alice Johnson");
    election.addCandidate("Bob Smith");
    election.addCandidate("Charlie Davis");

    election.registerVoter("VTR-1");
    election.registerVoter("VTR-2");
    election.registerVoter("VTR-3");
    election.registerVoter("VTR-4");

    election.castVote("VTR-1", "Alice Johnson");
    election.castVote("VTR-2", "Bob Smith");
    election.castVote("VTR-3", "Alice Johnson");
    election.castVote("VTR-4", "Charlie Davis");

    std::string report;
    auto tally = election.auditAndTallyVotes(&report);

    assert(tally["Alice Johnson"] == 2);
    assert(tally["Bob Smith"] == 1);
    assert(tally["Charlie Davis"] == 1);
    std::cout << "            -> PASSED: Vote tally verified.\n";
}

void testBallotReceiptVerification() {
    std::cout << "[TEST 9/17] Running Individual Verifiability (Ballot Receipt) test...\n";
    Election election("Faculty Senate 2026", 1);
    election.addCandidate("Dr. Turing");
    election.registerVoter("FAC-001");

    BallotReceipt receipt = election.castVoteWithReceipt("FAC-001", "Dr. Turing");
    assert(!receipt.getReceiptCode().empty());

    // Verify receipt against genuine chain
    std::string statusMsg;
    bool verified = election.verifyReceipt(receipt, &statusMsg);
    assert(verified);

    // Verify forged receipt is rejected
    BallotReceipt forged("BLT-FORGED", "fake_hash", receipt.getBlockIndex(), receipt.getBlockHash());
    bool forgedVerified = election.verifyReceipt(forged, &statusMsg);
    assert(!forgedVerified);
    std::cout << "            -> PASSED: Individual verifiability receipt verified and forgery rejected.\n";
}

void testLedgerStorageSaveAndLoad() {
    std::cout << "[TEST 10/17] Running Ledger Persistence (Save & Load) test...\n";
    Blockchain originalChain(1);
    originalChain.addBlock("VOTE_TX|BLT-1|hash1|Candidate A|2026-09-14 12:00:00 UTC|sig1");
    originalChain.addBlock("VOTE_TX|BLT-2|hash2|Candidate B|2026-09-14 12:01:00 UTC|sig2");

    std::string testFile = "data/test_ledger.dat";
    LedgerStorage::saveBlockchain(originalChain, testFile);

    Blockchain loadedChain = LedgerStorage::loadBlockchain(testFile);
    assert(loadedChain.getChainSize() == originalChain.getChainSize());
    assert(loadedChain.isChainValid());

    for (size_t i = 0; i < loadedChain.getChainSize(); ++i) {
        assert(loadedChain.getChain()[i].getHash() == originalChain.getChain()[i].getHash());
        assert(loadedChain.getChain()[i].getData() == originalChain.getChain()[i].getData());
    }
    std::cout << "             -> PASSED: Ledger successfully persisted to disk and verified on load.\n";
}

void testDiskTamperingDetection() {
    std::cout << "[TEST 11/17] Running Disk Tampering Detection test...\n";
    std::string testFile = "data/test_ledger_tamper.dat";

    Blockchain originalChain(1);
    originalChain.addBlock("Genuine Vote Payload 1");
    originalChain.addBlock("Genuine Vote Payload 2");
    LedgerStorage::saveBlockchain(originalChain, testFile);

    // Tamper with file directly on disk
    std::ifstream in(testFile);
    std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();

    // Replace a payload character in the file
    size_t pos = content.find("Genuine Vote Payload 1");
    if (pos != std::string::npos) {
        content.replace(pos, 22, "Tampered Malicious Vote");
    }
    std::ofstream out(testFile);
    out << content;
    out.close();

    // Attempting to load tampered file must fail cryptographic validation!
    bool tamperDetected = false;
    try {
        LedgerStorage::loadBlockchain(testFile);
    } catch (const BlockchainException&) {
        tamperDetected = true;
    }
    assert(tamperDetected);
    std::cout << "             -> PASSED: On-disk file corruption detected and rejected upon load.\n";
}

void testPasswordHashingAndVerification() {
    std::cout << "[TEST 12/17] Running Password Hashing and Verification test...\n";
    std::string pass1 = "MySecretPassword@2026";
    std::string hash1 = Authentication::hashPassword(pass1, 100);
    std::string hash2 = Authentication::hashPassword(pass1, 100);

    // Salt ensures hashes are unique even for same password
    assert(hash1 != hash2);

    // Verification succeeds with correct password
    assert(Authentication::verifyPassword(pass1, hash1));
    assert(Authentication::verifyPassword(pass1, hash2));

    // Verification fails with incorrect password
    assert(!Authentication::verifyPassword("WrongPassword!", hash1));
    assert(!Authentication::verifyPassword("mysecretpassword@2026", hash1));
    std::cout << "             -> PASSED: Salted multi-iteration password hashing verified.\n";
}

void testInputValidation() {
    std::cout << "[TEST 13/17] Running Input Validation test...\n";
    std::string err;
    // Valid usernames
    assert(Authentication::validateUsername("alice_101", &err));
    assert(Authentication::validateUsername("VTR-889", &err));
    assert(Authentication::validateUsername("admin_user", &err));

    // Invalid usernames
    assert(!Authentication::validateUsername("", &err));
    assert(!Authentication::validateUsername("ab", &err)); // Too short
    assert(!Authentication::validateUsername("user with spaces", &err));
    assert(!Authentication::validateUsername("user@invalid$char", &err));

    // Valid passwords
    assert(Authentication::validatePassword("Pass1234", &err));
    assert(Authentication::validatePassword("SuperLongSecretPassword#2026", &err));

    // Invalid passwords
    assert(!Authentication::validatePassword("", &err));
    assert(!Authentication::validatePassword("12345", &err)); // < 6 chars
    std::cout << "             -> PASSED: Username and password input validation rules enforced.\n";
}

void testAdminAuthentication() {
    std::cout << "[TEST 14/17] Running Admin Authentication test...\n";
    Authentication auth;
    auth.initializeAdmin("election_admin", "AdminMasterKey@2026");

    // Correct login
    assert(auth.authenticateAdmin("election_admin", "AdminMasterKey@2026"));

    // Incorrect password
    bool caught = false;
    try {
        auth.authenticateAdmin("election_admin", "WrongKey");
    } catch (const AuthException&) {
        caught = true;
    }
    assert(caught);
    std::cout << "             -> PASSED: Admin initialization and authentication verified.\n";
}

void testVoterRegistrationAndSession() {
    std::cout << "[TEST 15/17] Running Voter Registration and Session Generation test...\n";
    Authentication auth;
    auth.registerVoter("VTR-2001", "VoterSecret@2026");

    assert(auth.isVoterRegistered("VTR-2001"));

    // Authenticate and verify session payload
    VoterSession session = auth.authenticateVoter("VTR-2001", "VoterSecret@2026");
    assert(session.voterId == "VTR-2001");
    assert(!session.voterHash.empty());
    assert(!session.sessionToken.empty());
    std::cout << "             -> PASSED: Voter registration and authenticated session verified.\n";
}

void testAccountLockout() {
    std::cout << "[TEST 16/17] Running Brute-Force Lockout Defense test...\n";
    Authentication auth(3, 5); // 3 max attempts, 5 sec lockout
    auth.registerVoter("TARGET_VOTER", "RealPassword@123");

    // Attempt 1: Failed
    try { auth.authenticateVoter("TARGET_VOTER", "BadPass1"); } catch (const AuthException&) {}
    assert(!auth.isAccountLocked("TARGET_VOTER"));

    // Attempt 2: Failed
    try { auth.authenticateVoter("TARGET_VOTER", "BadPass2"); } catch (const AuthException&) {}
    assert(!auth.isAccountLocked("TARGET_VOTER"));

    // Attempt 3: Triggers lockout
    try { auth.authenticateVoter("TARGET_VOTER", "BadPass3"); } catch (const AuthException&) {}
    assert(auth.isAccountLocked("TARGET_VOTER"));

    // 4th attempt immediately rejected due to lockout
    bool lockoutRejected = false;
    try {
        auth.authenticateVoter("TARGET_VOTER", "RealPassword@123");
    } catch (const AuthException& ex) {
        lockoutRejected = true;
    }
    assert(lockoutRejected);

    // Reset lockout
    auth.resetLockout("TARGET_VOTER");
    assert(!auth.isAccountLocked("TARGET_VOTER"));

    // Now login succeeds
    VoterSession session = auth.authenticateVoter("TARGET_VOTER", "RealPassword@123");
    assert(session.voterId == "TARGET_VOTER");
    std::cout << "             -> PASSED: 3-attempt account lockout defense verified.\n";
}

void testElectionLifecycleAndCandidateRemoval() {
    std::cout << "[TEST 17/17] Running Election Lifecycle & Candidate Management test...\n";
    // Initialize election with autoStart = false
    Election election("Presidential 2026", 1, "ELECTION_SECRET_SALT_2026", false);
    assert(election.getElectionState() == ElectionState::NOT_STARTED);

    election.addCandidate("Candidate One");
    election.addCandidate("Temporary Candidate");
    election.registerVoter("VTR-TEST");

    // Remove candidate before election begins
    election.removeCandidate("Temporary Candidate");
    assert(!election.isCandidateValid("Temporary Candidate"));

    // Voting while NOT_STARTED should be rejected
    bool blockedBeforeStart = false;
    try {
        election.castVote("VTR-TEST", "Candidate One");
    } catch (const VotingException&) {
        blockedBeforeStart = true;
    }
    assert(blockedBeforeStart);

    // Start election
    election.startElection();
    assert(election.getElectionState() == ElectionState::IN_PROGRESS);

    // Candidate removal during election should be rejected
    bool removalBlocked = false;
    try {
        election.removeCandidate("Candidate One");
    } catch (const VotingException&) {
        removalBlocked = true;
    }
    assert(removalBlocked);

    // Voting in IN_PROGRESS succeeds
    std::string bId = election.castVote("VTR-TEST", "Candidate One");
    assert(!bId.empty());

    // End election
    election.endElection();
    assert(election.getElectionState() == ElectionState::ENDED);

    // Register a second voter
    election.registerVoter("VTR-TEST2");
    bool blockedAfterEnd = false;
    try {
        election.castVote("VTR-TEST2", "Candidate One");
    } catch (const VotingException&) {
        blockedAfterEnd = true;
    }
    assert(blockedAfterEnd);
    std::cout << "             -> PASSED: Election lifecycle and candidate removal enforced.\n";
}

void testDigitalSignatureValid() {
    std::cout << "[TEST 18/22] Running Digital Signature generation & valid verification test...\n";
    Crypto::KeyPair kp = Crypto::generateKeyPair(1024);
    assert(!kp.publicKey.empty());
    assert(!kp.privateKey.empty());

    std::string txData = "BLT-7001:voter_hash_x:Candidate Alice:2026-09-15 10:00:00 UTC";
    std::string signature = Crypto::signTransaction(txData, kp.privateKey);
    assert(!signature.empty());

    bool valid = Crypto::verifySignature(txData, signature, kp.publicKey);
    assert(valid);
    std::cout << "             -> PASSED: RSA digital signature generated and verified with public key.\n";
}

void testDigitalSignatureModifiedTransaction() {
    std::cout << "[TEST 19/22] Running Digital Signature tampered transaction rejection test...\n";
    Crypto::KeyPair kp = Crypto::generateKeyPair(1024);
    std::string genuineTx = "BLT-7002:voter_hash_y:Candidate Alice:2026-09-15 10:00:00 UTC";
    std::string signature = Crypto::signTransaction(genuineTx, kp.privateKey);

    // Tamper with candidate choice
    std::string modifiedTx = "BLT-7002:voter_hash_y:Candidate Bob:2026-09-15 10:00:00 UTC";
    bool valid = Crypto::verifySignature(modifiedTx, signature, kp.publicKey);
    assert(!valid);
    std::cout << "             -> PASSED: Tampered transaction rejected by digital signature verification.\n";
}

void testDigitalSignatureInvalidSignature() {
    std::cout << "[TEST 20/22] Running Digital Signature corrupted signature rejection test...\n";
    Crypto::KeyPair kp = Crypto::generateKeyPair(1024);
    std::string txData = "BLT-7003:voter_hash_z:Candidate Charlie:2026-09-15 10:00:00 UTC";
    std::string genuineSig = Crypto::signTransaction(txData, kp.privateKey);

    // Corrupt signature bytes
    std::string corruptedSig = genuineSig;
    corruptedSig[0] = (corruptedSig[0] == 'a') ? 'b' : 'a';
    corruptedSig[1] = (corruptedSig[1] == '1') ? '2' : '1';

    bool validCorrupted = Crypto::verifySignature(txData, corruptedSig, kp.publicKey);
    assert(!validCorrupted);

    // Completely malformed signature string
    bool validMalformed = Crypto::verifySignature(txData, "deadbeef1234", kp.publicKey);
    assert(!validMalformed);
    std::cout << "             -> PASSED: Corrupted and malformed signatures rejected.\n";
}

void testDigitalSignatureWrongPublicKey() {
    std::cout << "[TEST 21/22] Running Digital Signature wrong public key rejection test...\n";
    Crypto::KeyPair voterA = Crypto::generateKeyPair(1024);
    Crypto::KeyPair voterB = Crypto::generateKeyPair(1024);

    std::string txData = "BLT-7004:voter_hash_a:Candidate Alice:2026-09-15 10:00:00 UTC";
    std::string sigA = Crypto::signTransaction(txData, voterA.privateKey);

    // Attempt verification using Voter B's public key
    bool valid = Crypto::verifySignature(txData, sigA, voterB.publicKey);
    assert(!valid);
    std::cout << "             -> PASSED: Signature verification with wrong public key rejected.\n";
}

void testDigitalSignatureTransactionFlow() {
    std::cout << "[TEST 22/22] Running Full Digital Signature Voting Pipeline test...\n";
    // Create Election
    Election election("Digital Signature Audit Election", 1, "SALT_DS_2026");
    election.addCandidate("Dr. Turing");
    election.registerVoter("VTR-DS-01");

    const Voter* voter = election.getVoter("VTR-DS-01");
    assert(voter != nullptr);
    assert(!voter->getPublicKey().empty());
    assert(!voter->getPrivateKey().empty());

    // Cast vote: Create Vote -> Serialize Transaction -> Sign Transaction -> Verify Signature -> Add to Blockchain
    BallotReceipt receipt = election.castVoteWithReceipt("VTR-DS-01", "Dr. Turing");
    assert(!receipt.getReceiptCode().empty());

    // Verify block payload contains valid digital signature and public key
    const Block& latestBlock = election.getBlockchain().getLatestBlock();
    assert(Vote::isVotePayload(latestBlock.getData()));

    Vote deserialized = Vote::deserialize(latestBlock.getData());
    assert(deserialized.getBallotId() == receipt.getBallotId());
    assert(deserialized.getPublicKey() == voter->getPublicKey());
    assert(deserialized.isValid());

    // Audit blockchain
    std::string auditReport;
    auto tally = election.auditAndTallyVotes(&auditReport);
    assert(tally["Dr. Turing"] == 1);
    std::cout << "             -> PASSED: Transaction flow (Create->Serialize->Sign->Verify->Mine) verified.\n";
}

int main() {
    std::cout << "==========================================================\n";
    std::cout << "  RUNNING BLOCKCHAIN & VOTING SYSTEM UNIT TEST SUITE      \n";
    std::cout << "==========================================================\n";

    testSHA256StandardVectors();
    testGenesisBlock();
    testAddAndLinkBlocks();
    testTamperDetection();
    testVoteSerializationAndSignature();
    testElectionVotingAndDoubleVoting();
    testUnregisteredVoter();
    testElectionAuditAndTally();
    testBallotReceiptVerification();
    testLedgerStorageSaveAndLoad();
    testDiskTamperingDetection();
    testPasswordHashingAndVerification();
    testInputValidation();
    testAdminAuthentication();
    testVoterRegistrationAndSession();
    testAccountLockout();
    testElectionLifecycleAndCandidateRemoval();

    // Digital Signature Test Suite
    testDigitalSignatureValid();
    testDigitalSignatureModifiedTransaction();
    testDigitalSignatureInvalidSignature();
    testDigitalSignatureWrongPublicKey();
    testDigitalSignatureTransactionFlow();

    std::cout << "==========================================================\n";
    std::cout << "        ALL UNIT TESTS PASSED SUCCESSFULLY (22/22)        \n";
    std::cout << "==========================================================\n";
    return 0;
}
