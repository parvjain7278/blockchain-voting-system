cmake_minimum_required(VERSION 3.16)
project(BlockchainVotingSystem VERSION 1.0.0 LANGUAGES CXX)

# Require C++20
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Include header files
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# Source files
set(SOURCES
    src/Block.cpp
    src/Blockchain.cpp
    src/Crypto.cpp
    src/CryptoUtils.cpp
    src/Vote.cpp
    src/Voter.cpp
    src/Election.cpp
    src/BallotReceipt.cpp
    src/LedgerStorage.cpp
    src/Authentication.cpp
)

# Main executable target
add_executable(BlockchainVotingSystem src/main.cpp ${SOURCES})

# Windows Cryptographic Service Provider (CryptoAPI SHA-256)
if(WIN32)
    target_link_libraries(BlockchainVotingSystem PRIVATE advapi32)
endif()

# Compiler warnings
if(MSVC)
    target_compile_options(BlockchainVotingSystem PRIVATE /W4)
else()
    target_compile_options(BlockchainVotingSystem PRIVATE -Wall -Wextra -pedantic)
endif()

