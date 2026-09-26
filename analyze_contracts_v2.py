#!/usr/bin/env python3
"""
Analyse aller 3 Smart Contracts auf BASE Mainnet (optimiert)
"""
import os
from web3 import Web3
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# Web3 Setup
RPC_URL = os.getenv("BASE_ALCHEMY_API_URL") or os.getenv("BASE_RPC_URL", "https://mainnet.base.org")
w3 = Web3(Web3.HTTPProvider(RPC_URL))

# Contract Addresses (BASE Mainnet) mit ungefähren Deployment-Blöcken
CONTRACTS = {
    "Identity NFT": {
        "address": os.getenv("IDENTITY_NFT_ADDRESS", "0xF9ff5DC523927B9632049bd19e17B610E9197d53"),
        "from_block": 34300000
    },
    "Resonance Score": {
        "address": os.getenv("RESONANCE_SCORE_ADDRESS", "0x9A814DBF7E2352CE9eA6293b4b731B2a24800102"),
        "from_block": 34300000
    },
    "Resonance Registry": {
        "address": os.getenv("RESONANCE_REGISTRY_ADDRESS", "0xAAf30d96382D2409Cf1626095e97BEc1C59e5cdF"),
        "from_block": 34300000
    }
}

# Transfer Event Signature (für NFT Mints)
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

print("=" * 80)
print("📊 AERA SMART CONTRACTS - VOLLSTÄNDIGE ANALYSE")
print("=" * 80)
print(f"\n🌐 Verbunden mit: {RPC_URL}")
print(f"✅ Web3 Connected: {w3.is_connected()}")

latest_block = w3.eth.block_number
print(f"📍 Current Block: {latest_block:,}")

print("\n" + "=" * 80)
print("1️⃣ IDENTITY NFT CONTRACT")
print("=" * 80)

nft_addr = CONTRACTS["Identity NFT"]["address"]
nft_from = CONTRACTS["Identity NFT"]["from_block"]

print(f"📍 Address: {nft_addr}")
print(f"🔍 Scanning blocks {nft_from:,} → {latest_block:,} ({latest_block - nft_from:,} blocks)")

try:
    # Get Transfer events
    logs = w3.eth.get_logs({
        'address': nft_addr,
        'fromBlock': nft_from,
        'toBlock': 'latest',
        'topics': [TRANSFER_TOPIC]
    })
    
    print(f"\n📊 Total Transfer Events: {len(logs)}")
    
    # Count mints (from = 0x0)
    mints = [log for log in logs if log['topics'][1] == b'\x00' * 32]
    print(f"🎨 NFTs Minted: {len(mints)}")
    
    if mints:
        # First mint
        first_mint = mints[0]
        first_block_info = w3.eth.get_block(first_mint['blockNumber'])
        first_time = datetime.fromtimestamp(first_block_info['timestamp'])
        
        print(f"\n📅 Erster Mint:")
        print(f"   Block: {first_mint['blockNumber']:,}")
        print(f"   Zeit: {first_time.strftime('%d.%m.%Y %H:%M:%S')}")
        
        # Last mint
        last_mint = mints[-1]
        last_block_info = w3.eth.get_block(last_mint['blockNumber'])
        last_time = datetime.fromtimestamp(last_block_info['timestamp'])
        
        print(f"\n📅 Letzter Mint:")
        print(f"   Block: {last_mint['blockNumber']:,}")
        print(f"   Zeit: {last_time.strftime('%d.%m.%Y %H:%M:%S')}")
        print(f"   TX: {last_mint['transactionHash'].hex()}")
        
        # Decode token ID from topics[3]
        token_id = int.from_bytes(last_mint['topics'][3], byteorder='big')
        print(f"   Token ID: #{token_id}")
        
        # Get recipient
        recipient = '0x' + last_mint['topics'][2].hex()[-40:]
        print(f"   Empfänger: {recipient}")
        
        # Time since last mint
        time_since = datetime.now() - last_time
        hours = time_since.total_seconds() / 3600
        print(f"   ⏱️ Vor {hours:.1f} Stunden")
    
    # Get all unique token holders
    recipients = set()
    for mint in mints:
        recipient = '0x' + mint['topics'][2].hex()[-40:]
        recipients.add(recipient)
    
    print(f"\n👥 Unique NFT Holders: {len(recipients)}")
    
    # Mints per day
    if mints:
        time_span_days = (last_time - first_time).total_seconds() / 86400
        if time_span_days > 0:
            mints_per_day = len(mints) / time_span_days
            print(f"📈 Mints/Tag (Durchschnitt): {mints_per_day:.1f}")
    
except Exception as e:
    print(f"❌ Fehler: {e}")

print("\n" + "=" * 80)
print("2️⃣ RESONANCE SCORE CONTRACT")
print("=" * 80)

score_addr = CONTRACTS["Resonance Score"]["address"]
score_from = CONTRACTS["Resonance Score"]["from_block"]

print(f"📍 Address: {score_addr}")
print(f"🔍 Scanning blocks {score_from:,} → {latest_block:,}")

try:
    logs = w3.eth.get_logs({
        'address': score_addr,
        'fromBlock': score_from,
        'toBlock': 'latest'
    })
    
    print(f"\n📊 Total Events: {len(logs)}")
    
    if logs:
        # First event
        first_event = logs[0]
        first_block_info = w3.eth.get_block(first_event['blockNumber'])
        first_time = datetime.fromtimestamp(first_block_info['timestamp'])
        
        print(f"\n📅 Erste Aktivität:")
        print(f"   Block: {first_event['blockNumber']:,}")
        print(f"   Zeit: {first_time.strftime('%d.%m.%Y %H:%M:%S')}")
        
        # Last event
        last_event = logs[-1]
        last_block_info = w3.eth.get_block(last_event['blockNumber'])
        last_time = datetime.fromtimestamp(last_block_info['timestamp'])
        
        print(f"\n📅 Letzte Aktivität:")
        print(f"   Block: {last_event['blockNumber']:,}")
        print(f"   Zeit: {last_time.strftime('%d.%m.%Y %H:%M:%S')}")
        print(f"   TX: {last_event['transactionHash'].hex()}")
        
        time_since = datetime.now() - last_time
        hours = time_since.total_seconds() / 3600
        print(f"   ⏱️ Vor {hours:.1f} Stunden")
        
        # Count unique transactions
        unique_txs = set(log['transactionHash'] for log in logs)
        print(f"\n📈 Unique Transactions: {len(unique_txs)}")
        
        # Updates per day
        time_span_days = (last_time - first_time).total_seconds() / 86400
        if time_span_days > 0:
            updates_per_day = len(logs) / time_span_days
            print(f"📈 Updates/Tag (Durchschnitt): {updates_per_day:.1f}")
        
except Exception as e:
    print(f"❌ Fehler: {e}")

print("\n" + "=" * 80)
print("3️⃣ RESONANCE REGISTRY CONTRACT")
print("=" * 80)

registry_addr = CONTRACTS["Resonance Registry"]["address"]
registry_from = CONTRACTS["Resonance Registry"]["from_block"]

print(f"📍 Address: {registry_addr}")
print(f"🔍 Scanning blocks {registry_from:,} → {latest_block:,}")

try:
    logs = w3.eth.get_logs({
        'address': registry_addr,
        'fromBlock': registry_from,
        'toBlock': 'latest'
    })
    
    print(f"\n📊 Total Events: {len(logs)}")
    
    if logs:
        # First event
        first_event = logs[0]
        first_block_info = w3.eth.get_block(first_event['blockNumber'])
        first_time = datetime.fromtimestamp(first_block_info['timestamp'])
        
        print(f"\n📅 Erste Aktivität:")
        print(f"   Block: {first_event['blockNumber']:,}")
        print(f"   Zeit: {first_time.strftime('%d.%m.%Y %H:%M:%S')}")
        
        # Last event
        last_event = logs[-1]
        last_block_info = w3.eth.get_block(last_event['blockNumber'])
        last_time = datetime.fromtimestamp(last_block_info['timestamp'])
        
        print(f"\n📅 Letzte Aktivität:")
        print(f"   Block: {last_event['blockNumber']:,}")
        print(f"   Zeit: {last_time.strftime('%d.%m.%Y %H:%M:%S')}")
        print(f"   TX: {last_event['transactionHash'].hex()}")
        
        time_since = datetime.now() - last_time
        hours = time_since.total_seconds() / 3600
        print(f"   ⏱️ Vor {hours:.1f} Stunden")
        
        # Count unique transactions
        unique_txs = set(log['transactionHash'] for log in logs)
        print(f"\n📈 Unique Transactions: {len(unique_txs)}")
        
        # Try to identify InteractionRecorded events (4 topics)
        interaction_events = [log for log in logs if len(log['topics']) == 4]
        print(f"⛓️ InteractionRecorded Events: {len(interaction_events)}")
        
        if interaction_events:
            # Count unique users involved
            all_addresses = set()
            for event in interaction_events:
                # Topics[1] = initiator, Topics[2] = responder
                initiator = '0x' + event['topics'][1].hex()[-40:]
                responder = '0x' + event['topics'][2].hex()[-40:]
                all_addresses.add(initiator)
                all_addresses.add(responder)
            print(f"👥 Unique Users mit Interactions: {len(all_addresses)}")
        
        # Interactions per day
        if logs:
            time_span_days = (last_time - first_time).total_seconds() / 86400
            if time_span_days > 0:
                interactions_per_day = len(logs) / time_span_days
                print(f"📈 Interactions/Tag (Durchschnitt): {interactions_per_day:.1f}")
        
except Exception as e:
    print(f"❌ Fehler: {e}")

print("\n" + "=" * 80)
print("📊 GESAMTSTATISTIK")
print("=" * 80)

try:
    nft_events = len(w3.eth.get_logs({
        'address': nft_addr,
        'fromBlock': nft_from,
        'toBlock': 'latest'
    }))
    
    score_events = len(w3.eth.get_logs({
        'address': score_addr,
        'fromBlock': score_from,
        'toBlock': 'latest'
    }))
    
    registry_events = len(w3.eth.get_logs({
        'address': registry_addr,
        'fromBlock': registry_from,
        'toBlock': 'latest'
    }))
    
    total_events = nft_events + score_events + registry_events
    
    print(f"\n🎨 NFT Contract: {nft_events} events")
    print(f"📊 Score Contract: {score_events} events")
    print(f"⛓️ Registry Contract: {registry_events} events")
    print(f"\n💫 TOTAL EVENTS: {total_events}")
    
    print(f"\n🔗 BaseScan Links:")
    print(f"   NFT: https://basescan.org/address/{nft_addr}")
    print(f"   Score: https://basescan.org/address/{score_addr}")
    print(f"   Registry: https://basescan.org/address/{registry_addr}")
    
except Exception as e:
    print(f"❌ Fehler bei Gesamtstatistik: {e}")

print("\n" + "=" * 80)
print("✅ ANALYSE ABGESCHLOSSEN")
print("=" * 80)
