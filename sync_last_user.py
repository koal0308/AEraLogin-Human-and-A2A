from web3 import Web3
from dotenv import load_dotenv
import os
import json

load_dotenv()

rpc_url = os.getenv("BASE_ALCHEMY_API_URL") or os.getenv("BASE_RPC_URL", "https://mainnet.base.org")
score_address = os.getenv("RESONANCE_SCORE_ADDRESS", "0x9A814DBF7E2352CE9eA6293b4b731B2a24800102")
backend_key = os.getenv("BACKEND_PRIVATE_KEY")

w3 = Web3(Web3.HTTPProvider(rpc_url))
account = w3.eth.account.from_key(backend_key)

abi = json.loads('[{"inputs":[{"internalType":"address","name":"user","type":"address"},{"internalType":"uint256","name":"newAmount","type":"uint256"}],"name":"adminAdjust","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"user","type":"address"}],"name":"getResonance","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"}]')

contract = w3.eth.contract(address=score_address, abi=abi)

last_user = "0xfec66216a44ff64848a8a56cb2e25d3324bba0b3"
score = 50

print(f"🎯 Synchronisiere letzten User: {last_user}")

checksum = Web3.to_checksum_address(last_user)
tx = contract.functions.adminAdjust(checksum, score).build_transaction({
    'from': account.address,
    'nonce': w3.eth.get_transaction_count(account.address),
    'gas': 150000,
    'gasPrice': w3.eth.gas_price,
})

signed_tx = w3.eth.account.sign_transaction(tx, backend_key)
tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)

print(f"📤 TX: {tx_hash.hex()}")
print(f"⏳ Warte auf Bestätigung...")

receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

if receipt['status'] == 1:
    print(f"✅ SUCCESS! Gas: {receipt['gasUsed']:,}")
    print(f"🔗 https://basescan.org/tx/{tx_hash.hex()}")
    
    import time
    time.sleep(3)
    
    new_score = contract.functions.getResonance(checksum).call()
    print(f"📊 Score: {new_score}")
else:
    print(f"❌ FAILED!")

