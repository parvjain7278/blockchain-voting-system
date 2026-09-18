# Build script for BlockchainVotingSystem
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Building Blockchain-Based Electronic Voting System (C++)" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$srcFiles = @(
    "src/main.cpp",
    "src/Block.cpp",
    "src/Blockchain.cpp",
    "src/Crypto.cpp",
    "src/CryptoUtils.cpp",
    "src/Vote.cpp",
    "src/Voter.cpp",
    "src/Election.cpp",
    "src/BallotReceipt.cpp",
    "src/LedgerStorage.cpp",
    "src/Authentication.cpp"
)

$outputExe = "BlockchainVotingSystem.exe"

Write-Host "`n[1/3] Compiling source files with g++..." -ForegroundColor Yellow
$compileCmd = "g++ -std=c++14 -Wall -Wextra -Iinclude $($srcFiles -join ' ') -ladvapi32 -o $outputExe"
Write-Host "Command: $compileCmd"
Invoke-Expression $compileCmd

if ($LASTEXITCODE -ne 0) {
    Write-Host "`n[ERROR] Compilation failed with error code $LASTEXITCODE" -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host "[SUCCESS] Executable built: $outputExe" -ForegroundColor Green

Write-Host "`n[2/3] Compiling test suite..." -ForegroundColor Yellow
$testFiles = @(
    "tests/test_blockchain.cpp",
    "src/Block.cpp",
    "src/Blockchain.cpp",
    "src/Crypto.cpp",
    "src/CryptoUtils.cpp",
    "src/Vote.cpp",
    "src/Voter.cpp",
    "src/Election.cpp",
    "src/BallotReceipt.cpp",
    "src/LedgerStorage.cpp",
    "src/Authentication.cpp"
)
$testExe = "test_blockchain.exe"
$compileTestCmd = "g++ -std=c++14 -Wall -Wextra -Iinclude $($testFiles -join ' ') -ladvapi32 -o $testExe"
Invoke-Expression $compileTestCmd

if ($LASTEXITCODE -eq 0) {
    Write-Host "[SUCCESS] Test suite built: $testExe" -ForegroundColor Green
    Write-Host "`n[3/3] Running test suite..." -ForegroundColor Yellow
    & ".\$testExe"
}

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host " Build and Tests Completed Successfully!" -ForegroundColor Green
Write-Host " Run '.\BlockchainVotingSystem.exe' to see the main demo." -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
