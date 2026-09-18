#include "Election.h"
#include "Authentication.h"
#include "CryptoUtils.h"
#include "BallotReceipt.h"
#include "LedgerStorage.h"
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>

void runVoterMenu(Election& election, const VoterSession& session) {
    bool inVoterMenu = true;
    while (inVoterMenu) {
        std::cout << "\n=======================================================\n";
        std::cout << "                     VOTER MENU                        \n";
        std::cout << " Authenticated Voter ID: " << session.voterId << "\n";
        std::cout << " Election Status       : " << election.getElectionStateString() << "\n";
        std::cout << "=======================================================\n";
        std::cout << " 1. View Candidates\n";
        std::cout << " 2. Logout\n";
        std::cout << " 3. Cast Vote (Active Election)\n";
        std::cout << "=======================================================\n";
        std::cout << "Select option: ";

        int choice = 0;
        if (!(std::cin >> choice)) {
            break;
        }
        std::cin.ignore(10000, '\n');

        switch (choice) {
            case 1: {
                election.displayCandidates();
                // If election is active, prompt if user wishes to cast vote right now
                if (election.getElectionState() == ElectionState::IN_PROGRESS) {
                    std::cout << "\nWould you like to cast your vote now? (y/n): ";
                    std::string ans;
                    std::getline(std::cin, ans);
                    if (ans == "y" || ans == "Y") {
                        std::cout << "Enter candidate name: ";
                        std::string cand;
                        std::getline(std::cin, cand);
                        try {
                            BallotReceipt receipt = election.castVoteWithReceipt(session.voterId, cand);
                            std::cout << "\n[VOTE RECORDED] Your ballot has been cryptographically mined onto the blockchain!\n";
                            receipt.displayReceipt();
                        } catch (const std::exception& ex) {
                            std::cout << "\n[BALLOT REJECTED] " << ex.what() << "\n";
                        }
                    }
                }
                break;
            }
            case 2:
                inVoterMenu = false;
                std::cout << "[LOGGED OUT] Voter session terminated.\n";
                break;
            case 3: {
                if (election.getElectionState() != ElectionState::IN_PROGRESS) {
                    std::cout << "[NOTICE] Voting is only permitted when election is IN_PROGRESS.\n";
                    std::cout << "         Current status: " << election.getElectionStateString() << "\n";
                    break;
                }
                election.displayCandidates();
                std::cout << "Enter Candidate Name: ";
                std::string cand;
                std::getline(std::cin, cand);
                try {
                    BallotReceipt receipt = election.castVoteWithReceipt(session.voterId, cand);
                    std::cout << "\n[VOTE RECORDED] Your ballot has been cryptographically mined onto the blockchain!\n";
                    receipt.displayReceipt();
                } catch (const std::exception& ex) {
                    std::cout << "\n[BALLOT REJECTED] " << ex.what() << "\n";
                }
                break;
            }
            default:
                std::cout << "Invalid selection. Please enter 1, 2, or 3.\n";
                break;
        }
    }
}

void runAdminMenu(Election& election) {
    bool inAdminMenu = true;
    while (inAdminMenu) {
        std::cout << "\n=======================================================\n";
        std::cout << "                     ADMIN MENU                        \n";
        std::cout << " Election: " << election.getElectionName() << "\n";
        std::cout << " Status  : " << election.getElectionStateString() << "\n";
        std::cout << "=======================================================\n";
        std::cout << " 1. Add Candidate\n";
        std::cout << " 2. Remove Candidate\n";
        std::cout << " 3. View Candidates\n";
        std::cout << " 4. Register Voter\n";
        std::cout << " 5. Start Election\n";
        std::cout << " 6. End Election\n";
        std::cout << " 7. Logout\n";
        std::cout << "=======================================================\n";
        std::cout << "Select option [1-7]: ";

        int choice = 0;
        if (!(std::cin >> choice)) {
            break;
        }
        std::cin.ignore(10000, '\n');

        switch (choice) {
            case 1: {
                std::cout << "Enter Candidate Name: ";
                std::string name;
                std::getline(std::cin, name);
                try {
                    election.addCandidate(name);
                    std::cout << "[SUCCESS] Candidate '" << name << "' added to the official ballot.\n";
                } catch (const std::exception& ex) {
                    std::cout << "[ERROR] " << ex.what() << "\n";
                }
                break;
            }
            case 2: {
                election.displayCandidates();
                std::cout << "Enter Candidate Name to Remove: ";
                std::string name;
                std::getline(std::cin, name);
                try {
                    election.removeCandidate(name);
                    std::cout << "[SUCCESS] Candidate '" << name << "' removed.\n";
                } catch (const std::exception& ex) {
                    std::cout << "[ERROR] " << ex.what() << "\n";
                }
                break;
            }
            case 3:
                election.displayCandidates();
                break;
            case 4: {
                std::cout << "Enter new Voter ID: ";
                std::string vId;
                std::getline(std::cin, vId);
                std::cout << "Set Voter Password (min 6 characters): ";
                std::string pwd;
                std::getline(std::cin, pwd);
                try {
                    election.registerVoterWithPassword(vId, pwd);
                    std::cout << "[SUCCESS] Voter '" << vId << "' registered with salted cryptographic credentials.\n";
                } catch (const std::exception& ex) {
                    std::cout << "[ERROR] " << ex.what() << "\n";
                }
                break;
            }
            case 5: {
                try {
                    election.startElection();
                    std::cout << "[SUCCESS] Election STARTED! Voters may now cast ballots.\n";
                } catch (const std::exception& ex) {
                    std::cout << "[ERROR] " << ex.what() << "\n";
                }
                break;
            }
            case 6: {
                try {
                    election.endElection();
                    std::cout << "[SUCCESS] Election ENDED! Voting is now closed.\n";
                    std::cout << "\n>>> Running Final Cryptographic Audit & Official Results:\n";
                    election.displayElectionResults();
                } catch (const std::exception& ex) {
                    std::cout << "[ERROR] " << ex.what() << "\n";
                }
                break;
            }
            case 7:
                inAdminMenu = false;
                std::cout << "[LOGGED OUT] Admin session ended.\n";
                break;
            default:
                std::cout << "Invalid selection. Please choose 1-7.\n";
                break;
        }
    }
}

void runMainMenu(Election& election) {
    bool running = true;
    while (running) {
        std::cout << "\n=======================================================\n";
        std::cout << "      BLOCKCHAIN ELECTRONIC VOTING SYSTEM              \n";
        std::cout << "=======================================================\n";
        std::cout << " 1. Admin Login\n";
        std::cout << " 2. Voter Registration\n";
        std::cout << " 3. Voter Login\n";
        std::cout << " 4. View Candidates\n";
        std::cout << " 5. Exit\n";
        std::cout << "=======================================================\n";
        std::cout << "Select option [1-5]: ";

        int choice = 0;
        if (!(std::cin >> choice)) {
            break;
        }
        std::cin.ignore(10000, '\n');

        switch (choice) {
            case 1: {
                std::cout << "\n--- ADMIN AUTHENTICATION ---\n";
                std::cout << "Admin Username: ";
                std::string user;
                std::getline(std::cin, user);
                std::cout << "Admin Password: ";
                std::string pass;
                std::getline(std::cin, pass);

                try {
                    if (election.getAuth().authenticateAdmin(user, pass)) {
                        std::cout << "[AUTHENTICATION SUCCESS] Welcome, Administrator.\n";
                        runAdminMenu(election);
                    }
                } catch (const AuthException& ex) {
                    std::cout << "[ACCESS DENIED] " << ex.what() << "\n";
                }
                break;
            }
            case 2: {
                std::cout << "\n--- VOTER REGISTRATION ---\n";
                std::cout << "Choose a Voter ID (3-32 alphanumeric characters): ";
                std::string voterId;
                std::getline(std::cin, voterId);
                std::cout << "Create a Secure Password (min 6 characters): ";
                std::string pass1;
                std::getline(std::cin, pass1);
                std::cout << "Confirm Password: ";
                std::string pass2;
                std::getline(std::cin, pass2);

                if (pass1 != pass2) {
                    std::cout << "[ERROR] Passwords do not match. Registration cancelled.\n";
                    break;
                }

                try {
                    election.registerVoterWithPassword(voterId, pass1);
                    std::cout << "[SUCCESS] Voter account registered successfully!\n";
                    std::cout << "          Your password was salted and cryptographically hashed.\n";
                } catch (const std::exception& ex) {
                    std::cout << "[REGISTRATION FAILED] " << ex.what() << "\n";
                }
                break;
            }
            case 3: {
                std::cout << "\n--- VOTER AUTHENTICATION ---\n";
                std::cout << "Voter ID: ";
                std::string vId;
                std::getline(std::cin, vId);
                std::cout << "Password: ";
                std::string pwd;
                std::getline(std::cin, pwd);

                try {
                    VoterSession session = election.getAuth().authenticateVoter(vId, pwd);
                    std::cout << "[AUTHENTICATION SUCCESS] Welcome, Voter " << session.voterId << "!\n";
                    runVoterMenu(election, session);
                } catch (const AuthException& ex) {
                    std::cout << "[ACCESS DENIED] " << ex.what() << "\n";
                }
                break;
            }
            case 4:
                election.displayCandidates();
                break;
            case 5:
                running = false;
                std::cout << "\nExiting Blockchain Voting System. Goodbye!\n";
                break;
            default:
                std::cout << "Invalid option. Please choose 1-5.\n";
                break;
        }
    }
}

void runAutomatedDemonstration() {
    std::cout << "\n====================================================================================================\n";
    std::cout << "          SECURE BLOCKCHAIN-BASED ELECTRONIC VOTING SYSTEM (AUTOMATED DEMO)                         \n";
    std::cout << "====================================================================================================\n\n";

    // Initialize election with autoStart = false
    Election election("2026 Student Council Presidential Election", 2, "ELECTION_SECRET_SALT_2026", false);
    std::cout << "[INFO] Election created in state: " << election.getElectionStateString() << "\n";

    // Setup Admin account
    election.getAuth().initializeAdmin("admin", "AdminMasterKey@2026");
    std::cout << "[AUTH] Admin account initialized with salted multi-iteration hash: 'admin'\n";

    // Admin adds candidates
    std::cout << "\n>>> Admin registering candidates...\n";
    election.addCandidate("Alice Johnson");
    election.addCandidate("Bob Smith");
    election.addCandidate("Charlie Davis");
    election.displayCandidates();

    // Register voters with passwords
    std::cout << "\n>>> Registering voters with secure password hashing...\n";
    election.registerVoterWithPassword("VTR-1001", "Password1001!");
    election.registerVoterWithPassword("VTR-1002", "Password1002!");
    election.registerVoterWithPassword("VTR-1003", "Password1003!");
    std::cout << "[INFO] 3 voters registered. Passwords hashed with CSPRNG salts.\n";

    // Test voting blocked before election starts
    std::cout << "\n>>> Testing voting before election begins...\n";
    try {
        election.castVote("VTR-1001", "Alice Johnson");
    } catch (const VotingException& ex) {
        std::cout << "[DEFENSE CONFIRMED] " << ex.what() << "\n";
    }

    // Admin starts election
    std::cout << "\n>>> Admin starting election...\n";
    election.startElection();
    std::cout << "[STATUS] Election is now: " << election.getElectionStateString() << "\n";

    // Voters authenticate and cast votes
    std::cout << "\n>>> Voters authenticating and casting ballots...\n";
    VoterSession s1 = election.getAuth().authenticateVoter("VTR-1001", "Password1001!");
    std::cout << "[AUTH SUCCESS] Voter " << s1.voterId << " authenticated. Session token: " << s1.sessionToken.substr(0, 16) << "...\n";
    BallotReceipt r1 = election.castVoteWithReceipt("VTR-1001", "Alice Johnson");
    std::cout << "               Ballot recorded in Block #" << r1.getBlockIndex() << " | Receipt proof: " << r1.getReceiptCode().substr(0, 16) << "...\n";

    VoterSession s2 = election.getAuth().authenticateVoter("VTR-1002", "Password1002!");
    BallotReceipt r2 = election.castVoteWithReceipt("VTR-1002", "Bob Smith");
    std::cout << "[AUTH SUCCESS] Voter " << s2.voterId << " voted for Bob Smith.\n";

    // Test failed login and lockout
    std::cout << "\n>>> Testing failed login attempt on voter account...\n";
    try {
        election.getAuth().authenticateVoter("VTR-1003", "IncorrectPassword");
    } catch (const AuthException& ex) {
        std::cout << "[SECURITY CATCH] " << ex.what() << "\n";
    }

    // Now correct login
    VoterSession s3 = election.getAuth().authenticateVoter("VTR-1003", "Password1003!");
    election.castVoteWithReceipt("VTR-1003", "Alice Johnson");
    std::cout << "[AUTH SUCCESS] Voter " << s3.voterId << " authenticated and cast ballot.\n";

    // Admin ends election
    std::cout << "\n>>> Admin ending election...\n";
    election.endElection();
    std::cout << "[STATUS] Election is now: " << election.getElectionStateString() << "\n";

    // Digital Signatures Verification Demonstration
    std::cout << "\n>>> Demonstrating Cryptographic Digital Signature Verification & Defense...\n";
    Crypto::KeyPair demoKeys = Crypto::generateKeyPair(1024);
    std::string demoTx = "BLT-DEMO:voter_hash_demo:Alice Johnson:2026-09-15 12:00:00 UTC";
    std::string demoSig = Crypto::signTransaction(demoTx, demoKeys.privateKey);
    std::cout << "[DIGITAL SIGNATURE] RSA-2048/SHA-256 Signature generated: " << demoSig.substr(0, 32) << "...\n";
    bool validSig = Crypto::verifySignature(demoTx, demoSig, demoKeys.publicKey);
    std::cout << "[VERIFICATION] Signature verified against public key: " << (validSig ? "AUTHENTIC (VALID)" : "REJECTED") << "\n";
    std::string tamperedTx = "BLT-DEMO:voter_hash_demo:Bob Smith:2026-09-15 12:00:00 UTC";
    bool tamperedValid = Crypto::verifySignature(tamperedTx, demoSig, demoKeys.publicKey);
    std::cout << "[TAMPER DEFENSE] Tampered payload verification: " << (tamperedValid ? "COMPROMISED!" : "REJECTED (TAMPER DETECTED)") << "\n";

    // Display results
    election.displayElectionResults();
    std::cout << "====================================================================================================\n";
}

int main(int argc, char* argv[]) {
    try {
        std::cout << "====================================================================================================\n";
        std::cout << "          SECURE AND TAMPER-RESISTANT BLOCKCHAIN-BASED ELECTRONIC VOTING SYSTEM                    \n";
        std::cout << "                       C++20 Modular Blockchain & E-Voting Platform                                 \n";
        std::cout << "====================================================================================================\n";

        bool runDemo = false;
        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--demo" || arg == "-d") {
                runDemo = true;
            }
        }

        Election election("2026 Student Government Presidential Election", 2, "ELECTION_SECRET_SALT_2026", false);
        election.addCandidate("Alice Johnson");
        election.addCandidate("Bob Smith");
        election.addCandidate("Charlie Davis");

        // Seed initial admin account
        election.getAuth().initializeAdmin("admin", "AdminPassword@2026");

        // Seed demo voter accounts
        election.registerVoterWithPassword("VTR-1001", "Password@1001");
        election.registerVoterWithPassword("VTR-1002", "Password@1002");
        election.registerVoterWithPassword("VTR-1003", "Password@1003");

        if (runDemo) {
            runAutomatedDemonstration();
        } else {
            // Check if stdin is available
            if (!std::cin.eof()) {
                runMainMenu(election);
            } else {
                runAutomatedDemonstration();
            }
        }

    } catch (const Crypto::CryptoException& ex) {
        std::cerr << "[CRITICAL CRYPTO ERROR] " << ex.what() << std::endl;
        return 1;
    } catch (const AuthException& ex) {
        std::cerr << "[AUTH ERROR] " << ex.what() << std::endl;
        return 2;
    } catch (const VotingException& ex) {
        std::cerr << "[VOTING ERROR] " << ex.what() << std::endl;
        return 3;
    } catch (const std::exception& ex) {
        std::cerr << "[EXCEPTION] " << ex.what() << std::endl;
        return 4;
    }

    return 0;
}
