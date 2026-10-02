from web3 import Web3
import json

w3 = Web3(Web3.HTTPProvider("https://mainnet.base.org"))
tx_hash = "0x384e3028b9d4fedf9399a5a63533d2d98a915cacfbafbb71b6c2c87398e0f76a"

print("🔍 Transaction Check")
print("=" * 70)

receipt = w3.eth.get_transaction_receipt(tx_hash)
print(f"Status: {receipt['status']}")
print(f"Block: {receipt['blockNumber']}")
print(f"Gas Used: {receipt['gasUsed']:,}")

# Prüfe Score direkt
score_address = "0xD4676a88bfAD40A87c8a5e889EE4AdD1448527c4"
abi = json.loads('[{"inputs":[{"internalType":"address","name":"user","type":"address"}],"name":"getResonance","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"}]')

contract = w3.eth.contract(address=score_address, abi=abi)
user = "0xfec66216a44ff64848a8a56cb2e25d3324bba0b3"
checksum = Web3.to_checksum_address(user)

import time
for i in range(5):
    score = contract.functions.getResonance(checksum).call()
    print(f"Attempt {i+1}: Score = {score}")
    if score == 50:
        print("✅ Score gefunden!")
        break
    time.sleep(2)

