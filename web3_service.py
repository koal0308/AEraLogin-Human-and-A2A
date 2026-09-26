"""
VEra-Resonance — Web3 Service for BASE Mainnet
© 2025 Karlheinz Beismann — VEra-Resonance Project
Licensed under the Apache License, Version 2.0

Handles all blockchain interactions with BASE Mainnet smart contracts:
- Identity NFT minting and queries
- Resonance Score updates
- Interaction recording
- Token ID lookups
"""

import os
import asyncio
import aiohttp
from typing import Dict, Any, Optional, Tuple, List
from web3 import Web3
from web3.exceptions import ContractLogicError
from eth_account import Account
from logger import setup_logger

logger = setup_logger(__name__)


class Web3Service:
    """Service for interacting with BASE Mainnet blockchain"""
    
    def __init__(self):
        """Initialize Web3 connection and contract instances"""
        # Nonce lock to prevent concurrent transaction conflicts
        self._nonce_lock = asyncio.Lock()
        self._last_nonce = None
        self._last_nonce_time = 0
        
        # Load environment variables (will be loaded by server.py before import)
        # Prefer BASE_ALCHEMY_API_URL (reliable!), then BASE_RPC_URL, fallback to public RPC
        self.rpc_url = os.getenv("BASE_ALCHEMY_API_URL") or os.getenv("BASE_RPC_URL") or os.getenv("BASE_RPC_URL_PUBLIC", "https://mainnet.base.org")
        # Try BACKEND_PRIVATE_KEY first (has funds!), then fallback to others
        self.private_key = os.getenv("BACKEND_PRIVATE_KEY") or os.getenv("PRIVATE_KEY") or os.getenv("ADMIN_PRIVATE_KEY")
        
        # Contract addresses
        self.identity_nft_address = os.getenv("IDENTITY_NFT_ADDRESS")
        self.resonance_score_address = os.getenv("RESONANCE_SCORE_ADDRESS")
        self.resonance_registry_address = os.getenv("RESONANCE_REGISTRY_ADDRESS")
        
        # Profile NFT Contract (OPTIONAL - Public Display Layer)
        self.profile_nft_address = os.getenv("PROFILE_NFT_ADDRESS")
        
        # Blockscout API for event queries (BASE Mainnet)
        self.blockscout_api_url = os.getenv("BLOCKSCOUT_API_URL", "https://base.blockscout.com/api/v2")
        
        # Initialize Web3 (read-only mode if no PRIVATE_KEY)
        self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))
        
        if not self.private_key:
            logger.warning("⚠️ PRIVATE_KEY not found - Web3Service in READ-ONLY mode")
            logger.warning("⚠️ Blockchain queries work, but minting/transactions disabled")
            self.account = None
        else:
            self.account = Account.from_key(self.private_key)
            chain_id = int(os.getenv("BASE_NETWORK_CHAIN_ID", 8453))
            network_name = "BASE Mainnet" if chain_id == 8453 else f"BASE (Chain {chain_id})"
            logger.info(f"🌐 Connected to {network_name}: {self.rpc_url}")
            logger.info(f"💳 Backend Wallet: {self.account.address}")
        
        # Load contract ABIs and initialize contracts
        self._load_contracts()
        
    def _load_contracts(self):
        """Load smart contract instances"""
        # Identity NFT ABI (minimal - only functions we use)
        identity_abi = [
            {
                "inputs": [{"internalType": "address", "name": "to", "type": "address"}],
                "name": "mintIdentity",
                "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "inputs": [{"internalType": "address", "name": "owner", "type": "address"}],
                "name": "balanceOf",
                "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [{"internalType": "address", "name": "owner", "type": "address"}, {"internalType": "uint256", "name": "index", "type": "uint256"}],
                "name": "tokenOfOwnerByIndex",
                "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "anonymous": False,
                "inputs": [
                    {"indexed": True, "internalType": "address", "name": "from", "type": "address"},
                    {"indexed": True, "internalType": "address", "name": "to", "type": "address"},
                    {"indexed": True, "internalType": "uint256", "name": "tokenId", "type": "uint256"}
                ],
                "name": "Transfer",
                "type": "event"
            }
        ]
        
        # Resonance Score ABI
        score_abi = [
            {
                "inputs": [{"internalType": "address", "name": "user", "type": "address"}, {"internalType": "uint256", "name": "newAmount", "type": "uint256"}],
                "name": "adminAdjust",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "inputs": [{"internalType": "address", "name": "user", "type": "address"}],
                "name": "getResonance",
                "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
                "stateMutability": "view",
                "type": "function"
            }
        ]
        
        # Resonance Registry ABI
        registry_abi = [
            {
                "inputs": [
                    {"internalType": "address", "name": "follower", "type": "address"},
                    {"internalType": "address", "name": "creator", "type": "address"},
                    {"internalType": "bytes32", "name": "linkId", "type": "bytes32"},
                    {"internalType": "uint8", "name": "actionType", "type": "uint8"},
                    {"internalType": "uint256", "name": "weightFollower", "type": "uint256"},
                    {"internalType": "uint256", "name": "weightCreator", "type": "uint256"}
                ],
                "name": "recordInteraction",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "inputs": [{"internalType": "address", "name": "user", "type": "address"}, {"internalType": "uint256", "name": "offset", "type": "uint256"}, {"internalType": "uint256", "name": "limit", "type": "uint256"}],
                "name": "getUserInteractions",
                "outputs": [
                    {
                        "components": [
                            {"internalType": "address", "name": "initiator", "type": "address"},
                            {"internalType": "address", "name": "responder", "type": "address"},
                            {"internalType": "uint8", "name": "interactionType", "type": "uint8"},
                            {"internalType": "uint256", "name": "timestamp", "type": "uint256"},
                            {"internalType": "string", "name": "metadata", "type": "string"}
                        ],
                        "internalType": "struct InteractionData[]",
                        "name": "",
                        "type": "tuple[]"
                    }
                ],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "anonymous": False,
                "inputs": [
                    {"indexed": True, "internalType": "address", "name": "follower", "type": "address"},
                    {"indexed": True, "internalType": "address", "name": "creator", "type": "address"},
                    {"indexed": True, "internalType": "bytes32", "name": "linkId", "type": "bytes32"},
                    {"indexed": False, "internalType": "uint8", "name": "actionType", "type": "uint8"},
                    {"indexed": False, "internalType": "uint256", "name": "weightFollower", "type": "uint256"},
                    {"indexed": False, "internalType": "uint256", "name": "weightCreator", "type": "uint256"},
                    {"indexed": False, "internalType": "uint256", "name": "timestamp", "type": "uint256"}
                ],
                "name": "InteractionRecorded",
                "type": "event"
            }
        ]
        
        # Profile NFT ABI (OPTIONAL - Public Display Layer with Privacy Features)
        # Corrected ABI based on actual deployed contract
        profile_nft_abi = [
            {
                "inputs": [{"internalType": "address", "name": "to", "type": "address"}],
                "name": "mint",
                "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "inputs": [{"internalType": "uint256", "name": "tokenId", "type": "uint256"}],
                "name": "burn",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "inputs": [{"internalType": "address", "name": "", "type": "address"}],
                "name": "tokenOf",
                "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [{"internalType": "address", "name": "owner", "type": "address"}],
                "name": "balanceOf",
                "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [{"internalType": "uint256", "name": "tokenId", "type": "uint256"}],
                "name": "isPublic",
                "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [{"internalType": "uint256", "name": "tokenId", "type": "uint256"}, {"internalType": "bool", "name": "visibility", "type": "bool"}],
                "name": "setVisibility",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "inputs": [{"internalType": "uint256", "name": "tokenId", "type": "uint256"}],
                "name": "bumpMetadataNonce",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "inputs": [{"internalType": "uint256", "name": "tokenId", "type": "uint256"}],
                "name": "getMetadataNonce",
                "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [],
                "name": "soulboundMode",
                "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [{"internalType": "uint256", "name": "tokenId", "type": "uint256"}],
                "name": "tokenURI",
                "outputs": [{"internalType": "string", "name": "", "type": "string"}],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [],
                "name": "contractURI",
                "outputs": [{"internalType": "string", "name": "", "type": "string"}],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [],
                "name": "totalSupply",
                "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [{"internalType": "string", "name": "publicURI", "type": "string"}, {"internalType": "string", "name": "privateURI", "type": "string"}],
                "name": "setBaseURIs",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "inputs": [{"internalType": "string", "name": "uri", "type": "string"}],
                "name": "setContractURI",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "inputs": [{"internalType": "uint256", "name": "tokenId", "type": "uint256"}],
                "name": "getDelegate",
                "outputs": [{"internalType": "address", "name": "", "type": "address"}],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [{"internalType": "uint256", "name": "tokenId", "type": "uint256"}, {"internalType": "address", "name": "delegate", "type": "address"}],
                "name": "setDelegate",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "anonymous": False,
                "inputs": [
                    {"indexed": True, "internalType": "address", "name": "from", "type": "address"},
                    {"indexed": True, "internalType": "address", "name": "to", "type": "address"},
                    {"indexed": True, "internalType": "uint256", "name": "tokenId", "type": "uint256"}
                ],
                "name": "Transfer",
                "type": "event"
            },
            {
                "anonymous": False,
                "inputs": [
                    {"indexed": True, "internalType": "uint256", "name": "tokenId", "type": "uint256"},
                    {"indexed": False, "internalType": "bool", "name": "isPublic", "type": "bool"}
                ],
                "name": "VisibilityChanged",
                "type": "event"
            }
        ]
        
        # Initialize contract instances
        if self.identity_nft_address:
            self.identity_nft = self.w3.eth.contract(
                address=Web3.to_checksum_address(self.identity_nft_address),
                abi=identity_abi
            )
            logger.info(f"✅ Identity NFT Contract: {self.identity_nft_address}")
        else:
            logger.warning("⚠️ IDENTITY_NFT_ADDRESS not set")
            self.identity_nft = None
            
        if self.resonance_score_address:
            self.resonance_score = self.w3.eth.contract(
                address=Web3.to_checksum_address(self.resonance_score_address),
                abi=score_abi
            )
            logger.info(f"✅ Resonance Score Contract: {self.resonance_score_address}")
        else:
            logger.warning("⚠️ RESONANCE_SCORE_ADDRESS not set")
            self.resonance_score = None
            
        if self.resonance_registry_address:
            self.resonance_registry = self.w3.eth.contract(
                address=Web3.to_checksum_address(self.resonance_registry_address),
                abi=registry_abi
            )
            logger.info(f"✅ Resonance Registry Contract: {self.resonance_registry_address}")
        else:
            logger.warning("⚠️ RESONANCE_REGISTRY_ADDRESS not set")
            self.resonance_registry = None
        
        # Profile NFT Contract (OPTIONAL)
        if self.profile_nft_address:
            self.profile_nft = self.w3.eth.contract(
                address=Web3.to_checksum_address(self.profile_nft_address),
                abi=profile_nft_abi
            )
            logger.info(f"✅ Profile NFT Contract: {self.profile_nft_address}")
        else:
            logger.info("ℹ️ PROFILE_NFT_ADDRESS not set (optional)")
            self.profile_nft = None
    
    async def _get_next_nonce(self) -> int:
        """
        Thread-safe nonce management to prevent transaction conflicts.
        MUST be called under self._nonce_lock!
        """
        import time
        
        # Get current nonce from blockchain
        current_nonce = self.w3.eth.get_transaction_count(self.account.address, 'latest')
        
        # If we have a cached nonce and it's recent (< 30 seconds), use cached + 1
        if self._last_nonce is not None and (time.time() - self._last_nonce_time) < 30:
            # Use max to handle cases where blockchain nonce has advanced
            next_nonce = max(current_nonce, self._last_nonce + 1)
        else:
            next_nonce = current_nonce
        
        # Update cache
        self._last_nonce = next_nonce
        self._last_nonce_time = time.time()
        
        logger.info(f"🔢 Next nonce: {next_nonce} (blockchain: {current_nonce})")
        return next_nonce
    
    async def has_identity_nft(self, address: str) -> bool:
        """Check if address has an Identity NFT"""
        try:
            if not self.identity_nft:
                logger.warning("Identity NFT contract not initialized")
                return False
                
            checksum_address = Web3.to_checksum_address(address)
            balance = self.identity_nft.functions.balanceOf(checksum_address).call()
            
            # Balance > 0 means user has an NFT (balanceOf is reliable)
            return balance > 0
                
        except Exception as e:
            logger.error(f"Error checking NFT balance for {address}: {e}")
            return False
    
    async def get_identity_token_id(self, address: str) -> Optional[int]:
        """Get Identity NFT token ID for address"""
        try:
            if not self.identity_nft:
                return None
                
            checksum_address = Web3.to_checksum_address(address)
            balance = self.identity_nft.functions.balanceOf(checksum_address).call()
            
            if balance == 0:
                return None
            
            # FIXED: Try Transfer events FIRST (more reliable than tokenOfOwnerByIndex)
            token_id = await self._get_token_id_from_events(address)
            if token_id is not None:
                return token_id
            
            # Fallback: Try tokenOfOwnerByIndex (if contract supports enumeration)
            try:
                token_id = self.identity_nft.functions.tokenOfOwnerByIndex(checksum_address, 0).call()
                return int(token_id)
            except Exception:
                logger.warning(f"tokenOfOwnerByIndex not supported for {address}, event lookup also failed")
                return None
            
        except Exception as e:
            logger.error(f"Error getting token ID for {address}: {e}")
            return None
    
    async def _get_token_id_from_events(self, address: str) -> Optional[int]:
        """Fallback: Get token ID from mint transaction receipt"""
        try:
            # Try to get mint TX hash from database
            import sqlite3
            import os
            DB_PATH = os.path.join(os.path.dirname(__file__), "aera.db")
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT identity_mint_tx_hash FROM users WHERE address=?",
                (address.lower(),)
            )
            result = cursor.fetchone()
            conn.close()
            
            if not result or not result[0]:
                logger.warning(f"No mint TX hash found in DB for {address}")
                return None
            
            tx_hash = result[0]
            
            # Get transaction receipt
            receipt = self.w3.eth.get_transaction_receipt(tx_hash)
            
            if not receipt or receipt['status'] != 1:
                logger.warning(f"TX {tx_hash[:10]}... failed or not found for {address}")
                return None
            
            # Parse Transfer event from logs
            # Transfer(address indexed from, address indexed to, uint256 indexed tokenId)
            transfer_topic = self.w3.keccak(text='Transfer(address,address,uint256)').hex()
            
            for log in receipt['logs']:
                if log['topics'][0].hex() == transfer_topic:
                    # Token ID is in topics[3]
                    token_id = int(log['topics'][3].hex(), 16)
                    logger.info(f"✅ Found token ID {token_id} from TX receipt for {address}")
                    return token_id
            
            return None
            
        except Exception as e:
            logger.error(f"Error getting token ID from TX receipt for {address}: {e}")
            return None
    
    async def mint_identity_nft(self, address: str) -> Tuple[bool, Dict[str, Any]]:
        """Mint Identity NFT for address"""
        try:
            if not self.identity_nft:
                return False, {"error": "Identity NFT contract not initialized"}
            
            checksum_address = Web3.to_checksum_address(address)
            
            # Check if already has NFT
            if await self.has_identity_nft(address):
                logger.info(f"⚠️ Address {address} already has Identity NFT")
                token_id = await self.get_identity_token_id(address)
                return True, {
                    "message": "Already has Identity NFT",
                    "token_id": token_id,
                    "address": address
                }
            
            # Build transaction with proper nonce management (LOCK!)
            async with self._nonce_lock:
                nonce = await self._get_next_nonce()
                
                mint_tx = self.identity_nft.functions.mintIdentity(checksum_address).build_transaction({
                    'from': self.account.address,
                    'nonce': nonce,
                    'gas': 200000,
                    'maxFeePerGas': self.w3.eth.gas_price * 2,
                    'maxPriorityFeePerGas': self.w3.eth.gas_price,
                    'chainId': 8453
                })
                
                # Sign and send transaction
                signed_tx = self.w3.eth.account.sign_transaction(mint_tx, self.private_key)
                raw_tx = getattr(signed_tx, 'rawTransaction', getattr(signed_tx, 'raw_transaction', None))
                if raw_tx is None:
                    raise ValueError("Could not get raw transaction from signed transaction")
                
                tx_hash = self.w3.eth.send_raw_transaction(raw_tx)
                tx_hash_hex = tx_hash.hex()
                
                logger.info(f"📤 NFT mint transaction sent: {tx_hash_hex}")
                logger.info(f"   → For: {address}")
                logger.info(f"   → Nonce: {nonce}")
            
            # Wait for confirmation
            logger.info(f"⏳ Waiting for NFT mint confirmation...")
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
            
            if receipt['status'] == 1:
                logger.info(f"✅ NFT minted successfully! Block: {receipt['blockNumber']}")
            else:
                logger.error(f"❌ NFT mint transaction FAILED!")
            
            return True, {
                "tx_hash": tx_hash_hex,
                "status": "success" if receipt['status'] == 1 else "failed",
                "address": address,
                "block_number": receipt['blockNumber'],
                "basescan_url": f"https://basescan.org/tx/{tx_hash_hex}"
            }
            
        except ContractLogicError as e:
            logger.error(f"Contract error minting NFT for {address}: {e}")
            return False, {"error": f"Contract error: {str(e)}"}
        except Exception as e:
            logger.error(f"Error minting NFT for {address}: {e}")
            return False, {"error": str(e)}
    
    async def get_blockchain_score(self, address: str) -> int:
        """Get Resonance Score from blockchain"""
        try:
            if not self.resonance_score:
                logger.warning("Resonance Score contract not initialized")
                return 0
            
            checksum_address = Web3.to_checksum_address(address)
            score = self.resonance_score.functions.getResonance(checksum_address).call()
            return int(score)
            
        except Exception as e:
            logger.error(f"Error getting blockchain score for {address}: {e}")
            return 0
    
    async def update_blockchain_score(self, address: str, score: int) -> Tuple[bool, Dict[str, Any]]:
        """Update Resonance Score on blockchain"""
        try:
            if not self.resonance_score:
                return False, {"error": "Resonance Score contract not initialized"}
            
            checksum_address = Web3.to_checksum_address(address)
            
            # Build transaction with proper nonce management (LOCK!)
            async with self._nonce_lock:
                nonce = await self._get_next_nonce()
                
                update_tx = self.resonance_score.functions.adminAdjust(
                    checksum_address, 
                    score
                ).build_transaction({
                    'from': self.account.address,
                    'nonce': nonce,
                    'gas': 100000,
                    'maxFeePerGas': self.w3.eth.gas_price * 2,
                    'maxPriorityFeePerGas': self.w3.eth.gas_price,
                    'chainId': 8453
                })
                
                # Sign and send
                signed_tx = self.w3.eth.account.sign_transaction(update_tx, self.private_key)
                raw_tx = getattr(signed_tx, 'rawTransaction', getattr(signed_tx, 'raw_transaction', None))
                if raw_tx is None:
                    raise ValueError("Could not get raw transaction from signed transaction")
                
                tx_hash = self.w3.eth.send_raw_transaction(raw_tx)
                tx_hash_hex = tx_hash.hex()
                
                logger.info(f"� Score update transaction sent: {tx_hash_hex}")
                logger.info(f"   → Address: {address}")
                logger.info(f"   → Score: {score}")
                logger.info(f"   → Nonce: {nonce}")
            
            # Wait for confirmation
            logger.info(f"⏳ Waiting for score update confirmation...")
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
            
            if receipt['status'] == 1:
                logger.info(f"✅ Score updated successfully! Block: {receipt['blockNumber']}")
            else:
                logger.error(f"❌ Score update FAILED!")
            
            return True, {
                "tx_hash": tx_hash_hex,
                "status": "success" if receipt['status'] == 1 else "failed",
                "score": score,
                "block_number": receipt['blockNumber'],
                "basescan_url": f"https://basescan.org/tx/{tx_hash_hex}"
            }
            
        except Exception as e:
            logger.error(f"Error updating score for {address}: {e}")
            return False, {"error": str(e)}
    
    async def record_interaction(
        self, 
        initiator: str, 
        responder: str, 
        interaction_type: int,
        metadata: str = ""
    ) -> Tuple[bool, Dict[str, Any]]:
        """Record interaction on blockchain
        
        Contract expects 6 parameters:
        - follower (address): initiator of interaction
        - creator (address): responder/recipient
        - linkId (bytes32): unique identifier (hash of metadata)
        - actionType (uint8): interaction type (0=FOLLOW, etc.)
        - weightFollower (uint256): initiator's resonance score
        - weightCreator (uint256): responder's resonance score
        """
        try:
            if not self.resonance_registry:
                return False, {"error": "Resonance Registry contract not initialized"}
            
            initiator_addr = Web3.to_checksum_address(initiator)
            responder_addr = Web3.to_checksum_address(responder)
            
            # Generate linkId from metadata (hash it to bytes32)
            link_id = Web3.keccak(text=metadata) if metadata else Web3.keccak(text=f"{initiator}:{responder}:{interaction_type}")
            
            # Weights auf 1 setzen (Minimum) - Contract validiert weight > 0
            # Scores werden durch Milestone-System + Follow-Bonus verwaltet
            # Minimale Weights (1) vermeiden Double-Minting aber erfüllen Contract-Validierung
            weight_initiator = 1
            weight_responder = 1
            
            # Build transaction with proper nonce management (LOCK to prevent race conditions!)
            async with self._nonce_lock:
                nonce = await self._get_next_nonce()
                
                record_tx = self.resonance_registry.functions.recordInteraction(
                    initiator_addr,          # follower
                    responder_addr,          # creator
                    link_id,                 # linkId (bytes32)
                    interaction_type,        # actionType (uint8)
                    weight_initiator,        # weightFollower (uint256)
                    weight_responder         # weightCreator (uint256)
                ).build_transaction({
                    'from': self.account.address,
                    'nonce': nonce,
                    'gas': 500000,
                    'maxFeePerGas': self.w3.eth.gas_price * 2,
                    'maxPriorityFeePerGas': self.w3.eth.gas_price,
                    'chainId': 8453
                })
                
                # Sign and send
                signed_tx = self.w3.eth.account.sign_transaction(record_tx, self.private_key)
                raw_tx = getattr(signed_tx, 'rawTransaction', getattr(signed_tx, 'raw_transaction', None))
                if raw_tx is None:
                    raise ValueError("Could not get raw transaction from signed transaction")
                
                tx_hash = self.w3.eth.send_raw_transaction(raw_tx)
                tx_hash_hex = tx_hash.hex()
                
                logger.info(f"📤 Interaction transaction sent: {tx_hash_hex}")
                logger.info(f"   → Initiator: {initiator}")
                logger.info(f"   → Responder: {responder}")
                logger.info(f"   → Type: {interaction_type}")
                logger.info(f"   → Nonce: {nonce}")
            
            # ✅ WAIT FOR RECEIPT - This is the critical fix!
            logger.info(f"⏳ Waiting for transaction receipt...")
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
            
            # Check if transaction was successful
            if receipt['status'] == 1:
                logger.info(f"✅ [BLOCKCHAIN] Interaction recorded on-chain successfully!")
                logger.info(f"   → Block: {receipt['blockNumber']}")
                logger.info(f"   → Gas used: {receipt['gasUsed']}")
                status = "success"
            else:
                logger.error(f"❌ [BLOCKCHAIN] Transaction FAILED on-chain!")
                logger.error(f"   → Receipt: {receipt}")
                status = "failed"
            
            return True, {
                "tx_hash": tx_hash_hex,
                "status": status,
                "block_number": receipt['blockNumber'],
                "gas_used": receipt['gasUsed'],
                "basescan_url": f"https://basescan.org/tx/{tx_hash_hex}"
            }
            
        except Exception as e:
            logger.error(f"Error recording interaction: {e}")
            return False, {"error": str(e)}
    
    async def get_user_interactions(
        self, 
        address: str, 
        offset: int = 0, 
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """Get user interactions from blockchain using Blockscout API"""
        try:
            if not self.resonance_registry:
                logger.warning("Resonance Registry contract not initialized")
                return []
            
            checksum_address = Web3.to_checksum_address(address)
            
            logger.info(f"🔍 Querying Blockscout for interactions of {checksum_address}")
            
            # Get all logs from the Registry contract using Blockscout API
            # Blockscout automatically decodes events!
            all_events = await self._get_events_from_blockscout(
                contract_address=self.resonance_registry_address
            )
            
            # Filter for events where user is follower OR creator
            user_events = []
            for event in all_events:
                if not event.get('decoded'):
                    continue
                
                params = event['decoded'].get('parameters', [])
                follower = None
                creator = None
                
                for param in params:
                    if param['name'] == 'follower':
                        follower = param['value']
                    elif param['name'] == 'creator':
                        creator = param['value']
                
                # Check if user is involved
                if follower and follower.lower() == checksum_address.lower():
                    user_events.append(event)
                elif creator and creator.lower() == checksum_address.lower():
                    user_events.append(event)
            
            # Sort by block number (newest first)
            user_events.sort(key=lambda x: x.get('block_number', 0), reverse=True)
            
            # Apply pagination
            paginated_events = user_events[offset:offset + limit]
            
            # Format response
            result = []
            for event in paginated_events:
                decoded = event.get('decoded', {})
                params = decoded.get('parameters', [])
                
                # Extract parameters
                param_dict = {p['name']: p['value'] for p in params}
                
                result.append({
                    "initiator": param_dict.get('follower', ''),
                    "responder": param_dict.get('creator', ''),
                    "interaction_type": int(param_dict.get('actionType', 0)),
                    "timestamp": int(param_dict.get('timestamp', 0)),
                    "link_id": param_dict.get('linkId', '0x0'),
                    "weight_follower": int(param_dict.get('weightFollower', 0)),
                    "weight_creator": int(param_dict.get('weightCreator', 0)),
                    "tx_hash": event.get('transaction_hash', ''),
                    "block_number": event.get('block_number', 0)
                })
            
            logger.info(f"✅ Found {len(result)} interactions for {checksum_address}")
            return result
            
        except Exception as e:
            logger.error(f"Error getting interactions for {address}: {e}")
            return []
    
    async def get_user_interaction_count(self, address: str) -> int:
        """
        Get the total number of interactions for a wallet from AEraResonanceRegistry
        This represents the user's "Your Score" - each interaction = 1 point
        
        Returns:
            int: Total number of interactions (initiator OR responder)
        """
        try:
            if not self.resonance_registry:
                logger.warning("Resonance Registry contract not initialized")
                return 0
            
            checksum_address = Web3.to_checksum_address(address)
            
            logger.info(f"🔍 Counting interactions for {checksum_address[:10]}...")
            
            # Get all events from Registry
            all_events = await self._get_events_from_blockscout(
                contract_address=self.resonance_registry_address
            )
            
            # Count events where user is follower OR creator
            count = 0
            for event in all_events:
                if not event.get('decoded'):
                    continue
                
                params = event['decoded'].get('parameters', [])
                follower = None
                creator = None
                
                for param in params:
                    if param['name'] == 'follower':
                        follower = param['value']
                    elif param['name'] == 'creator':
                        creator = param['value']
                
                # Count if user is involved
                if follower and follower.lower() == checksum_address.lower():
                    count += 1
                elif creator and creator.lower() == checksum_address.lower():
                    count += 1
            
            logger.info(f"✅ Interaction count for {checksum_address[:10]}...: {count}")
            return count
            
        except Exception as e:
            logger.error(f"Error counting interactions for {address}: {e}")
            return 0
    
    async def _get_events_from_blockscout(
        self,
        contract_address: str
    ) -> List[Dict[str, Any]]:
        """Get events from Blockscout API (auto-decodes events!)"""
        try:
            # Blockscout V2 API endpoint for contract logs
            url = f"{self.blockscout_api_url}/addresses/{contract_address}/logs"
            
            # Make async HTTP request
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    if response.status != 200:
                        logger.error(f"Blockscout API error: {response.status}")
                        return []
                    
                    data = await response.json()
                    
                    # Blockscout returns {"items": [...]} 
                    return data.get('items', [])
                    
        except Exception as e:
            logger.error(f"Error fetching events from Blockscout: {e}")
            return []
    
    async def get_blockchain_health(self) -> Dict[str, Any]:
        """Get blockchain connection health status"""
        try:
            # Test connection
            block_number = self.w3.eth.block_number
            gas_price = self.w3.eth.gas_price
            chain_id = int(os.getenv("BASE_NETWORK_CHAIN_ID", 8453))
            
            result = {
                "status": "connected",
                "block_number": block_number,
                "gas_price_gwei": float(Web3.from_wei(gas_price, 'gwei')),
                "rpc_url": self.rpc_url,
                "chain_id": chain_id,
                "network": "BASE Mainnet" if chain_id == 8453 else f"BASE (Chain {chain_id})"
            }
            
            # Add backend wallet info if available
            if self.account:
                balance = self.w3.eth.get_balance(self.account.address)
                balance_eth = Web3.from_wei(balance, 'ether')
                result["backend_balance_eth"] = float(balance_eth)
                result["backend_address"] = self.account.address
            else:
                result["mode"] = "read-only"
            
            return result
            
        except Exception as e:
            logger.error(f"Blockchain health check failed: {e}")
            return {
                "status": "disconnected",
                "error": str(e)
            }

    # ============================================
    # PROFILE NFT FUNCTIONS (OPTIONAL - Public Display Layer)
    # ============================================
    
    async def has_profile_nft(self, address: str) -> bool:
        """Check if address has an optional Profile NFT using balanceOf"""
        try:
            if not self.profile_nft:
                logger.debug("Profile NFT contract not initialized (optional)")
                return False
            
            checksum_address = Web3.to_checksum_address(address)
            # Use balanceOf - returns > 0 if user has a token
            balance = self.profile_nft.functions.balanceOf(checksum_address).call()
            return balance > 0
            
        except Exception as e:
            logger.error(f"Error checking Profile NFT for {address}: {e}")
            return False
    
    async def get_profile_token_id(self, address: str) -> Optional[int]:
        """Get Profile NFT token ID for address using tokenOf"""
        try:
            if not self.profile_nft:
                return None
            
            checksum_address = Web3.to_checksum_address(address)
            # tokenOf returns 0 if no token, otherwise returns the token ID
            token_id = self.profile_nft.functions.tokenOf(checksum_address).call()
            
            if token_id == 0:
                return None
            
            return int(token_id)
            
        except Exception as e:
            logger.error(f"Error getting Profile token ID for {address}: {e}")
            return None
    
    async def get_profile_visibility(self, token_id: int) -> bool:
        """Check if Profile NFT is PUBLIC (visible on marketplaces)"""
        try:
            if not self.profile_nft:
                return False
            
            is_public = self.profile_nft.functions.isPublic(token_id).call()
            return is_public
            
        except Exception as e:
            logger.error(f"Error checking Profile visibility for token {token_id}: {e}")
            return False
    
    async def get_profile_data(self, address: str) -> Optional[Dict[str, Any]]:
        """Get all Profile NFT data for an address"""
        try:
            if not self.profile_nft:
                return None
            
            checksum_address = Web3.to_checksum_address(address)
            # Use tokenOf - returns 0 if no token
            token_id = self.profile_nft.functions.tokenOf(checksum_address).call()
            
            if token_id == 0:
                return None
            
            is_public = self.profile_nft.functions.isPublic(token_id).call()
            metadata_nonce = self.profile_nft.functions.getMetadataNonce(token_id).call()
            token_uri = self.profile_nft.functions.tokenURI(token_id).call()
            soulbound = self.profile_nft.functions.soulboundMode().call()
            
            return {
                "token_id": int(token_id),
                "is_public": is_public,
                "metadata_nonce": int(metadata_nonce),
                "token_uri": token_uri,
                "soulbound_mode": soulbound,
                "contract_address": self.profile_nft_address
            }
            
        except Exception as e:
            logger.error(f"Error getting Profile data for {address}: {e}")
            return None
    
    async def mint_profile_nft(self, address: str) -> Tuple[bool, Dict[str, Any]]:
        """Mint a new Profile NFT for a user (USER-INITIATED ONLY!)"""
        try:
            if not self.profile_nft:
                return False, {"error": "Profile NFT contract not configured"}
            
            if not self.account:
                return False, {"error": "Backend wallet not configured"}
            
            checksum_address = Web3.to_checksum_address(address)
            
            # Check if user already has a token using balanceOf
            balance = self.profile_nft.functions.balanceOf(checksum_address).call()
            if balance > 0:
                token_id = self.profile_nft.functions.tokenOf(checksum_address).call()
                return False, {"error": f"User already has Profile NFT #{token_id}"}
            
            logger.info(f"🎨 Minting Profile NFT for {checksum_address[:10]}...")
            
            async with self._nonce_lock:
                nonce = await self._get_next_nonce()
                
                # Build mint transaction
                tx = self.profile_nft.functions.mint(checksum_address).build_transaction({
                    'from': self.account.address,
                    'nonce': nonce,
                    'gas': 250000,
                    'maxFeePerGas': self.w3.eth.gas_price * 2,
                    'maxPriorityFeePerGas': self.w3.to_wei(0.001, 'gwei'),
                    'chainId': int(os.getenv("BASE_NETWORK_CHAIN_ID", 8453))
                })
                
                # Sign and send
                signed_tx = self.account.sign_transaction(tx)
                tx_hash = self.w3.eth.send_raw_transaction(signed_tx.raw_transaction)
                
                logger.info(f"📤 Profile NFT mint TX sent: {tx_hash.hex()[:20]}...")
                
                # Wait for confirmation
                receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
                
                if receipt['status'] != 1:
                    return False, {"error": "Transaction failed", "tx_hash": tx_hash.hex()}
                
                # Extract token ID from Transfer event
                transfer_event = self.profile_nft.events.Transfer().process_receipt(receipt)
                if transfer_event:
                    token_id = transfer_event[0]['args']['tokenId']
                else:
                    # Fallback: query directly
                    token_id = self.profile_nft.functions.tokenOf(checksum_address).call()
                
                logger.info(f"✅ Profile NFT #{token_id} minted for {checksum_address[:10]}!")
                
                return True, {
                    "token_id": int(token_id),
                    "tx_hash": tx_hash.hex(),
                    "contract_address": self.profile_nft_address
                }
                
        except Exception as e:
            logger.error(f"Error minting Profile NFT for {address}: {e}")
            return False, {"error": str(e)}
    
    async def burn_profile_nft(self, token_id: int) -> Tuple[bool, Dict[str, Any]]:
        """Burn a Profile NFT (requires MINTER_ROLE)"""
        try:
            if not self.profile_nft:
                return False, {"error": "Profile NFT contract not configured"}
            
            if not self.account:
                return False, {"error": "Backend wallet not configured"}
            
            logger.info(f"🔥 Burning Profile NFT #{token_id}...")
            
            async with self._nonce_lock:
                nonce = await self._get_next_nonce()
                
                tx = self.profile_nft.functions.burn(token_id).build_transaction({
                    'from': self.account.address,
                    'nonce': nonce,
                    'gas': 150000,
                    'maxFeePerGas': self.w3.eth.gas_price * 2,
                    'maxPriorityFeePerGas': self.w3.to_wei(0.001, 'gwei'),
                    'chainId': int(os.getenv("BASE_NETWORK_CHAIN_ID", 8453))
                })
                
                signed_tx = self.account.sign_transaction(tx)
                tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)
                
                receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
                
                if receipt['status'] != 1:
                    return False, {"error": "Burn transaction failed", "tx_hash": tx_hash.hex()}
                
                logger.info(f"✅ Profile NFT #{token_id} burned!")
                
                return True, {"tx_hash": tx_hash.hex()}
                
        except Exception as e:
            logger.error(f"Error burning Profile NFT #{token_id}: {e}")
            return False, {"error": str(e)}
    
    async def get_profile_total_supply(self) -> int:
        """Get total number of minted Profile NFTs"""
        try:
            if not self.profile_nft:
                return 0
            
            return self.profile_nft.functions.totalSupply().call()
            
        except Exception as e:
            logger.error(f"Error getting Profile NFT total supply: {e}")
            return 0
    
    async def get_profile_delegate(self, token_id: int) -> Optional[str]:
        """Get the delegate address for a Profile NFT token"""
        try:
            if not self.profile_nft:
                return None
            
            delegate = self.profile_nft.functions.getDelegate(token_id).call()
            return delegate if delegate != "0x0000000000000000000000000000000000000000" else None
            
        except Exception as e:
            logger.error(f"Error getting delegate for Profile NFT #{token_id}: {e}")
            return None
    
    async def is_backend_delegate(self, token_id: int) -> bool:
        """Check if the backend wallet is set as delegate for this token"""
        try:
            if not self.profile_nft or not self.account:
                return False
            
            delegate = await self.get_profile_delegate(token_id)
            return delegate and delegate.lower() == self.account.address.lower()
            
        except Exception as e:
            logger.error(f"Error checking delegate status for Profile NFT #{token_id}: {e}")
            return False
    
    async def set_profile_visibility(self, token_id: int, is_public: bool) -> Tuple[bool, Dict[str, Any]]:
        """
        Set visibility of a Profile NFT (PUBLIC or PRIVATE)
        
        Args:
            token_id: The token ID
            is_public: True for public, False for private
            
        Returns:
            (success, result_dict)
        """
        try:
            if not self.profile_nft or not self.account:
                return False, {"error": "Profile NFT or backend wallet not configured"}
            
            logger.info(f"Setting visibility for Profile NFT #{token_id} to {'PUBLIC' if is_public else 'PRIVATE'}")
            
            # Build transaction using the backend account
            nonce = self.w3.eth.get_transaction_count(self.account.address)
            
            tx = self.profile_nft.functions.setVisibility(
                token_id,
                is_public
            ).build_transaction({
                'from': self.account.address,
                'nonce': nonce,
                'gas': 100000,
                'maxFeePerGas': self.w3.to_wei(0.1, 'gwei'),
                'maxPriorityFeePerGas': self.w3.to_wei(0.05, 'gwei'),
                'chainId': 8453  # Base Mainnet
            })
            
            # Sign and send
            signed_tx = self.account.sign_transaction(tx)
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.raw_transaction)
            
            logger.info(f"Visibility TX sent: {tx_hash.hex()}")
            
            # Wait for confirmation
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
            
            if receipt['status'] == 1:
                logger.info(f"✅ Visibility set successfully for Profile NFT #{token_id}")
                return True, {"tx_hash": tx_hash.hex(), "is_public": is_public}
            else:
                return False, {"error": "Transaction failed", "tx_hash": tx_hash.hex()}
                
        except Exception as e:
            logger.error(f"Error setting visibility for Profile NFT #{token_id}: {e}")
            return False, {"error": str(e)}
    
    async def increment_metadata_nonce(self, token_id: int) -> Tuple[bool, Dict[str, Any]]:
        """
        Increment the metadata nonce to force OpenSea to refresh
        
        This triggers EIP-4906 MetadataUpdate event.
        
        Args:
            token_id: The token ID
            
        Returns:
            (success, result_dict)
        """
        try:
            if not self.profile_nft or not self.account:
                return False, {"error": "Profile NFT or backend wallet not configured"}
            
            logger.info(f"Bumping metadata nonce for Profile NFT #{token_id}")
            
            # Build transaction - use bumpMetadataNonce (correct function name)
            nonce = self.w3.eth.get_transaction_count(self.account.address)
            
            tx = self.profile_nft.functions.bumpMetadataNonce(
                token_id
            ).build_transaction({
                'from': self.account.address,
                'nonce': nonce,
                'gas': 80000,
                'maxFeePerGas': self.w3.to_wei(0.1, 'gwei'),
                'maxPriorityFeePerGas': self.w3.to_wei(0.05, 'gwei'),
                'chainId': 8453  # Base Mainnet
            })
            
            # Sign and send
            signed_tx = self.account.sign_transaction(tx)
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.raw_transaction)
            
            logger.info(f"Metadata nonce TX sent: {tx_hash.hex()}")
            
            # Wait for confirmation
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
            
            if receipt['status'] == 1:
                # Get new nonce value
                new_nonce = self.profile_nft.functions.getMetadataNonce(token_id).call()
                logger.info(f"✅ Metadata nonce bumped to {new_nonce} for Profile NFT #{token_id}")
                return True, {"tx_hash": tx_hash.hex(), "new_nonce": new_nonce}
            else:
                return False, {"error": "Transaction failed", "tx_hash": tx_hash.hex()}
                
        except Exception as e:
            logger.error(f"Error bumping metadata nonce for Profile NFT #{token_id}: {e}")
            return False, {"error": str(e)}


# Global instance
web3_service = Web3Service()
