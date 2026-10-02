from web3 import Web3
import json

w3 = Web3(Web3.HTTPProvider("https://mainnet.base.org"))
score_address = "0xD4676a88bfAD40A87c8a5e889EE4AdD1448527c4"

abi = json.loads('[{"inputs":[{"internalType":"address","name":"user","type":"address"}],"name":"getResonance","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"}]')

contract = w3.eth.contract(address=score_address, abi=abi)

# Test Wallets aus dem Sync
test_wallets = [
    ("0x0e8cdfb710e88a6da418895c8b36ecedf242fe70", 51),
    ("0x1d35789beeb4f5aaff6ee1db4f2f20103d699976", 50),
    ("0x9ad57e3950ca5dc763ef15ce4b271dcb6005983b", 51),
    ("0x73f0d7243d546d8abb1364e0adaf1bb926c665d7", 55),
]

print("🔍 BLOCKCHAIN SCORE VERIFICATION")
print("=" * 70)

for wallet, expected in test_wallets:
    checksum = Web3.to_checksum_address(wallet)
    score = contract.functions.getResonance(checksum).call()
    status = "✅" if score == expected else "⚠️"
    print(f"{status} {wallet[:10]}... Expected: {expected}, Got: {score}")

print("=" * 70)
