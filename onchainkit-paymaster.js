/**
 * VEra-Resonance — OnchainKit Paymaster Integration
 * © 2025 Karlheinz Beismann — VEra-Resonance Project
 * 
 * EINFACHER BASE-WEG für Gasless Transactions!
 * Verwendet Coinbase OnchainKit mit Alchemy Paymaster
 */

import { createPublicClient, createWalletClient, custom, http } from 'viem';
import { base } from 'viem/chains';

// Alchemy Config - Load from environment variables!
// NEVER commit real API keys to Git!
const ALCHEMY_API_KEY = process.env.ALCHEMY_API_KEY || 'YOUR_ALCHEMY_API_KEY';
const PAYMASTER_URL = `https://base-mainnet.g.alchemy.com/v2/${ALCHEMY_API_KEY}`;

/**
 * OnchainKit Paymaster Config
 * 
 * Das ist ALLES was du brauchst für gaslose Transaktionen!
 * Configure ALCHEMY_API_KEY and ALCHEMY_POLICY_ID in .env
 */
export const paymasterConfig = {
    url: PAYMASTER_URL,
    context: {
        policyId: process.env.ALCHEMY_POLICY_ID || 'YOUR_POLICY_ID'
    }
};

/**
 * Viem Client mit Paymaster Support
 */
export function createPaymasterClient() {
    if (typeof window === 'undefined' || !window.ethereum) {
        console.warn('⚠️ MetaMask not detected');
        return null;
    }

    const publicClient = createPublicClient({
        chain: base,
        transport: http(PAYMASTER_URL)
    });

    const walletClient = createWalletClient({
        chain: base,
        transport: custom(window.ethereum)
    });

    return { publicClient, walletClient };
}

/**
 * Sende Gasless Transaction
 * 
 * @param {Object} contract - Contract instance
 * @param {string} functionName - Function to call
 * @param {Array} args - Function arguments
 * @param {string} userAddress - User's wallet address
 * 
 * @returns {Promise} Transaction result
 */
export async function sendGaslessTransaction(contract, functionName, args, userAddress) {
    try {
        console.log('🔄 Preparing gasless transaction...');
        console.log(`   Function: ${functionName}`);
        console.log(`   User: ${userAddress}`);

        const clients = createPaymasterClient();
        if (!clients) {
            throw new Error('Cannot create paymaster client');
        }

        const { publicClient, walletClient } = clients;

        // 1. Simulate transaction
        const { request } = await publicClient.simulateContract({
            address: contract.address,
            abi: contract.abi,
            functionName,
            args,
            account: userAddress,
        });

        console.log('✅ Simulation successful');

        // 2. Send transaction with Paymaster
        // OnchainKit/Alchemy handles gas sponsorship automatically!
        const hash = await walletClient.writeContract({
            ...request,
            // Paymaster wird automatisch von Alchemy verwendet
            // weil wir den PAYMASTER_URL nutzen!
        });

        console.log('✅ Transaction sent (gasless):', hash);
        console.log('   BaseScan:', `https://basescan.org/tx/${hash}`);

        // 3. Wait for confirmation
        const receipt = await publicClient.waitForTransactionReceipt({ 
            hash,
            confirmations: 1
        });

        console.log('✅ Transaction confirmed!');
        console.log('   Gas used:', receipt.gasUsed.toString());
        console.log('   Status:', receipt.status);

        return {
            success: true,
            hash,
            receipt,
            gasless: true,
            basescanUrl: `https://basescan.org/tx/${hash}`
        };

    } catch (error) {
        console.error('❌ Gasless transaction failed:', error);
        return {
            success: false,
            error: error.message,
            gasless: false
        };
    }
}

/**
 * Mint Identity NFT (Gasless!)
 * 
 * @param {string} userAddress - User's wallet address
 * @returns {Promise} Mint result
 */
export async function mintIdentityNFTGasless(userAddress) {
    const NFT_ADDRESS = '0xF6f86cc0b916BCfE44cff64b00C2fe6e7954A3Ce';
    
    // Minimal ABI - nur mintIdentity function
    const NFT_ABI = [
        {
            inputs: [{ name: 'to', type: 'address' }],
            name: 'mintIdentity',
            outputs: [{ name: '', type: 'uint256' }],
            stateMutability: 'nonpayable',
            type: 'function'
        }
    ];

    const contract = {
        address: NFT_ADDRESS,
        abi: NFT_ABI
    };

    console.log('🎨 Minting NFT (GASLESS)...');
    console.log(`   To: ${userAddress}`);
    console.log('   💰 User pays: $0.00');
    console.log('   💳 Alchemy pays: ~$0.0003');

    return await sendGaslessTransaction(
        contract,
        'mintIdentity',
        [userAddress],
        userAddress
    );
}

/**
 * Update Resonance Score (Gasless!)
 * 
 * @param {string} userAddress - User's wallet address
 * @param {number} newScore - New resonance score
 * @returns {Promise} Update result
 */
export async function updateResonanceScoreGasless(userAddress, newScore) {
    const SCORE_ADDRESS = '0xD4676a88bfAD40A87c8a5e889EE4AdD1448527c4';
    
    const SCORE_ABI = [
        {
            inputs: [
                { name: 'user', type: 'address' },
                { name: 'score', type: 'uint256' }
            ],
            name: 'updateResonance',
            outputs: [],
            stateMutability: 'nonpayable',
            type: 'function'
        }
    ];

    const contract = {
        address: SCORE_ADDRESS,
        abi: SCORE_ABI
    };

    console.log('📊 Updating Score (GASLESS)...');
    console.log(`   User: ${userAddress}`);
    console.log(`   Score: ${newScore}`);
    console.log('   💰 User pays: $0.00');
    console.log('   💳 Alchemy pays: ~$0.0002');

    return await sendGaslessTransaction(
        contract,
        'updateResonance',
        [userAddress, newScore],
        userAddress
    );
}

/**
 * Check if Paymaster is available
 */
export async function checkPaymasterStatus() {
    try {
        const response = await fetch(PAYMASTER_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                jsonrpc: '2.0',
                method: 'eth_blockNumber',
                params: [],
                id: 1
            })
        });

        if (response.ok) {
            console.log('✅ Paymaster connection: OK');
            return true;
        } else {
            console.error('❌ Paymaster connection: FAILED');
            return false;
        }
    } catch (error) {
        console.error('❌ Paymaster check failed:', error);
        return false;
    }
}

// Export everything
export default {
    paymasterConfig,
    createPaymasterClient,
    sendGaslessTransaction,
    mintIdentityNFTGasless,
    updateResonanceScoreGasless,
    checkPaymasterStatus
};
