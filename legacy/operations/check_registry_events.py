from web3 import Web3
import json

w3 = Web3(Web3.HTTPProvider("https://mainnet.base.org"))

# Die erfolgreiche Transaction
tx_hash = "0x167d6d53f6af58a8aba0ebcf46aef6591db2d36f8398c8e843168154e6e9b7f8"

print("🔍 Analysiere Registry Transaction")
print("=" * 70)

# Hole Transaction Receipt
receipt = w3.eth.get_transaction_receipt(tx_hash)

print(f"Status: {'✅ Success' if receipt['status'] == 1 else '❌ Failed'}")
print(f"Gas Used: {receipt['gasUsed']:,}")
print(f"Logs Count: {len(receipt['logs'])}")
print("\n📋 EVENTS/LOGS:")

for i, log in enumerate(receipt['logs']):
    print(f"\nLog {i+1}:")
    print(f"  Contract: {log['address']}")
    print(f"  Topics: {len(log['topics'])}")
    for j, topic in enumerate(log['topics']):
        print(f"    Topic {j}: {topic.hex()}")
    print(f"  Data: {log['data'][:100]}..." if len(log['data']) > 100 else f"  Data: {log['data']}")

print("\n" + "=" * 70)
print("💡 TIP: Gehe zu BaseScan und schaue unter 'Logs' Tab:")
print(f"https://basescan.org/tx/{tx_hash}#eventlog")

