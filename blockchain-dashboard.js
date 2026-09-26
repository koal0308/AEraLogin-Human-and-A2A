/**
 * blockchain-dashboard.js
 * Blockchain integration for VEra Dashboard
 * Loads on-chain data: Identity NFT,        } catch (error) {
            console.error('[Blockchain] NFT check error:', error);
            updateElement('identityStatus', `
                <span style="color: #f44336;">❌</span> <span style="color: #f0f4ff;">Error</span>
                <br>
                <small style="color: #f0f4ff;">${error.message}</small>
            `);nce Score, Interaction History
 */

window.BlockchainDashboard = (function() {
    'use strict';

    const API_BASE = window.location.origin || 'http://localhost:8840';

    // ==================== HELPER FUNCTIONS ====================

    function updateElement(elementId, content) {
        const el = document.getElementById(elementId);
        if (el) {
            el.innerHTML = content;
        } else {
            console.warn(`[Blockchain] Element not found: ${elementId}`);
        }
    }

    function formatAddress(address) {
        if (!address || address.length < 10) return address;
        return `${address.substring(0, 6)}...${address.substring(address.length - 4)}`;
    }

    function formatTimestamp(timestamp) {
        if (!timestamp) return 'N/A';
        
        // Handle both Unix timestamps (numbers) and ISO strings (strings)
        let date;
        if (typeof timestamp === 'number') {
            // Blockchain timestamps are in seconds, JavaScript Date expects milliseconds
            date = new Date(timestamp * 1000);
        } else if (typeof timestamp === 'string') {
            // API timestamps like "2025-12-01 16:20:48"
            date = new Date(timestamp);
        } else {
            return 'Invalid Date';
        }
        
        // Check if date is valid
        if (isNaN(date.getTime())) {
            return 'Invalid Date';
        }
        
        return date.toLocaleString('de-DE', {
            day: '2-digit',
            month: '2-digit',
            year: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    }

    // ==================== NFT LOADING ====================

    async function loadIdentityNFT(address) {
        console.log('[Blockchain] Loading Identity NFT for:', address);
        
        try {
            const response = await fetch(`${API_BASE}/api/blockchain/identity/${address}`);
            const data = await response.json();

            console.log('[Blockchain] NFT status:', data);

            if (data.has_identity && data.token_id) {
                const tokenId = data.token_id;
                const explorerUrl = data.basescan_url || `https://basescan.org/nft/${data.contract_address}/${tokenId}`;
                
                updateElement('identityStatus', `
                    <span style="color: #4caf50;">✅</span> <span style="color: #f0f4ff;">Minted</span>
                    <br>
                    <small style="color: #f0f4ff;">Token #${tokenId}</small>
                    <br>
                    <a href="${explorerUrl}" target="_blank" style="color: #2196f3; font-size: 12px;">
                        View on BaseScan →
                    </a>
                `);
                
                // 🔥 Hide Gasless Mint button (NFT already minted)
                const mintBtn = document.getElementById('mintGaslessBtn');
                if (mintBtn) {
                    mintBtn.style.display = 'none';
                    console.log('[Blockchain] ✅ Gasless Mint button hidden (NFT already minted)');
                }
            } else if (data.identity_status === 'minting') {
                updateElement('identityStatus', `
                    <span style="color: #ff9800;">⏳</span> <span style="color: #f0f4ff;">Minting...</span>
                    <br>
                    <small style="color: #f0f4ff;">Please wait 30-60 seconds</small>
                `);
            } else if (data.identity_status === 'failed') {
                updateElement('identityStatus', `
                    <span style="color: #f44336;">❌</span> <span style="color: #f0f4ff;">Mint Failed</span>
                    <br>
                    <small style="color: #f0f4ff;">Contact support</small>
                `);
            } else {
                updateElement('identityStatus', `
                    <span style="color: #9e9e9e;">⏳</span> <span style="color: #f0f4ff;">Not Minted</span>
                    <br>
                    <small style="color: #f0f4ff;">Will auto-mint on first login</small>
                `);
                
                // 🔥 Show Gasless Mint button if NFT not minted
                const mintBtn = document.getElementById('mintGaslessBtn');
                if (mintBtn) {
                    mintBtn.style.display = 'block';
                    console.log('[Blockchain] 🔥 Gasless Mint button shown (NFT not minted)');
                }
            }
        } catch (error) {
            console.error('[Blockchain] NFT load error:', error);
            updateElement('identityStatus', `
                <span style="color: #f44336;">❌</span> Error
                <br>
                <small>${error.message}</small>
            `);
        }
    }

    // ==================== SCORE LOADING ====================

    async function loadResonanceScore(address) {
        console.log('[Blockchain] Loading Resonance Score for:', address);
        
        try {
            const response = await fetch(`${API_BASE}/api/blockchain/score/${address}`);
            const data = await response.json();

            console.log('[Blockchain] Score data:', data);

            // NEW: Use Resonance fields
            const ownScore = data.own_score || 0;
            const followerBonus = data.follower_bonus || 0;
            const followerCount = data.follower_count || 0;
            const totalResonance = data.total_resonance || 0;
            const chainScore = data.blockchain_score || 0;
            const syncPending = data.sync_pending || 0;
            const lastSync = data.last_sync ? formatTimestamp(data.last_sync) : 'Never';

            // Update combined score display with Resonance breakdown
            updateElement('blockchainScore', `
                <span style="color: #4caf50;">✅</span> <span style="color: #f0f4ff;">${chainScore}</span>
                <br>
                <small style="font-size: 11px; opacity: 0.85; color: #f0f4ff;">
                    Own: ${ownScore} + Follower Bonus: ${followerBonus}
                    ${followerCount > 0 ? ` (${followerCount} followers)` : ''}
                </small>
            `);

            // Sync status indicator - Compare totalResonance with chainScore
            let syncIcon = '🔄';
            let syncColor = '#ff9800';
            let syncText = 'Pending';
            
            if (totalResonance === chainScore && chainScore > 0) {
                syncIcon = '✅';
                syncColor = '#4caf50';
                syncText = 'Synced';
            } else if (Math.abs(syncPending) > 0) {
                syncIcon = '⏳';
                syncColor = '#ff9800';
                syncText = `Pending (${syncPending > 0 ? '+' : ''}${syncPending})`;
            } else if (lastSync === 'Never') {
                syncIcon = '⏸️';
                syncColor = '#9e9e9e';
                syncText = 'Not Started';
            }

            updateElement('syncStatus', `
                <span style="color: ${syncColor};">${syncIcon}</span> <span style="color: #f0f4ff;">${syncText}</span>
                <br>
                <small style="font-size: 10px; color: #f0f4ff;">${lastSync}</small>
            `);

        } catch (error) {
            console.error('[Blockchain] Score load error:', error);
            updateElement('blockchainScore', '<span style="color: #f44336;">❌</span>');
            updateElement('syncStatus', `
                <span style="color: #f44336;">❌</span> <span style="color: #f0f4ff;">Error</span>
                <br>
                <small style="font-size: 10px; color: #f0f4ff;">Check console</small>
            `);
        }
    }

    // ==================== INTERACTION HISTORY ====================

    async function loadInteractionHistory(address) {
        console.log('[Blockchain] Loading Interaction History for:', address);
        
        try {
            const response = await fetch(`${API_BASE}/api/blockchain/interactions/${address}?limit=10`);
            const data = await response.json();

            console.log('[Blockchain] Interaction data:', data);

            const historyContainer = document.getElementById('interactionsContainer');
            if (!historyContainer) {
                console.warn('[Blockchain] interactionsContainer not found');
                return;
            }

            if (!data.interactions || data.interactions.length === 0) {
                historyContainer.innerHTML = `
                    <div style="text-align: center; padding: 20px; color: #9e9e9e;">
                        <p>No interactions recorded yet</p>
                        <small>Start following other users to see activity here</small>
                    </div>
                `;
                return;
            }

            // Build interaction list
            let html = '<table style="width: 100%; border-collapse: collapse;">';
            html += '<thead><tr>';
            html += '<th style="text-align: left; padding: 8px; border-bottom: 1px solid #333;">Type</th>';
            html += '<th style="text-align: left; padding: 8px; border-bottom: 1px solid #333;">With</th>';
            html += '<th style="text-align: left; padding: 8px; border-bottom: 1px solid #333;">Date</th>';
            html += '<th style="text-align: center; padding: 8px; border-bottom: 1px solid #333;">TX</th>';
            html += '</tr></thead>';
            html += '<tbody>';

            data.interactions.forEach((interaction, index) => {
                const typeName = (interaction.interaction_type_name || 'UNKNOWN').toUpperCase();
                // ✅ FIX: Case-insensitive comparison to correctly identify the other party
                const otherAddress = interaction.initiator.toLowerCase() === address.toLowerCase()
                    ? interaction.responder 
                    : interaction.initiator;
                const timestamp = formatTimestamp(interaction.timestamp);
                const txHash = interaction.tx_hash || '';

                // Determine role: initiator (you follow) or responder (follower)
                const isInitiator = interaction.initiator.toLowerCase() === address.toLowerCase();
                let displayType = typeName;
                let typeIcon = '🔗';
                
                if (typeName === 'FOLLOW') {
                    if (isInitiator) {
                        typeIcon = '➡️';
                        displayType = 'FOLLOWING'; // You follow someone
                    } else {
                        typeIcon = '⬅️';
                        displayType = 'FOLLOWER'; // Someone follows you
                    }
                } else if (typeName === 'SHARE') typeIcon = '📤';
                else if (typeName === 'ENGAGE') typeIcon = '💬';
                else if (typeName === 'COLLABORATE') typeIcon = '🤝';
                else if (typeName === 'MILESTONE') typeIcon = '🏆';

                html += '<tr style="border-bottom: 1px solid #222;">';
                html += `<td style="padding: 8px;">${typeIcon} ${displayType}</td>`;
                html += `<td style="padding: 8px; font-family: monospace; font-size: 11px;">${formatAddress(otherAddress)}</td>`;
                html += `<td style="padding: 8px; font-size: 11px;">${timestamp}</td>`;
                
                if (txHash) {
                    const txUrl = `https://basescan.org/tx/${txHash}`;
                    html += `<td style="padding: 8px; text-align: center;">
                        <a href="${txUrl}" target="_blank" style="color: #2196f3; text-decoration: none;">
                            🔗
                        </a>
                    </td>`;
                } else {
                    html += `<td style="padding: 8px; text-align: center; color: #666;">—</td>`;
                }
                
                html += '</tr>';
            });

            html += '</tbody></table>';
            historyContainer.innerHTML = html;

        } catch (error) {
            console.error('[Blockchain] Interaction history load error:', error);
            const historyContainer = document.getElementById('interactionsContainer');
            if (historyContainer) {
                historyContainer.innerHTML = `
                    <div style="text-align: center; padding: 20px; color: #f44336;">
                        <p>❌ Error loading interaction history</p>
                        <small>${error.message}</small>
                    </div>
                `;
            }
        }
    }

    // ==================== BLOCKCHAIN HEALTH ====================

    async function loadBlockchainHealth() {
        console.log('[Blockchain] Checking blockchain health...');
        
        try {
            const response = await fetch(`${API_BASE}/api/blockchain/stats`);
            const data = await response.json();

            console.log('[Blockchain] Health data:', data);

            const statusEl = document.getElementById('blockchainHealth');
            if (!statusEl) return;

            // Check blockchain_health nested object
            const health = data.blockchain_health || {};
            
            if (health.status === 'connected') {
                statusEl.innerHTML = `
                    <span style="color: #4caf50;">🟢</span> <span style="color: #f0f4ff;">Online</span>
                    <br>
                    <small style="font-size: 10px; color: #f0f4ff;">Block ${health.block_number || 'N/A'}</small>
                `;
            } else {
                statusEl.innerHTML = `
                    <span style="color: #f44336;">🔴</span> <span style="color: #f0f4ff;">Offline</span>
                    <br>
                    <small style="font-size: 10px; color: #f0f4ff;">${health.error || 'Connection error'}</small>
                `;
            }

        } catch (error) {
            console.error('[Blockchain] Health check error:', error);
            const statusEl = document.getElementById('blockchainHealth');
            if (statusEl) {
                statusEl.innerHTML = `
                    <span style="color: #f44336;">🔴</span> <span style="color: #f0f4ff;">Error</span>
                    <br>
                    <small style="font-size: 10px; color: #f0f4ff;">Check console</small>
                `;
            }
        }
    }

    // ==================== MAIN LOADER ====================

    async function loadBlockchainData(address) {
        console.log('🔗 [BlockchainDashboard] Starting blockchain data load for:', address);

        if (!address || !address.startsWith('0x') || address.length !== 42) {
            console.error('[Blockchain] Invalid address:', address);
            return;
        }

        // Load all blockchain data in parallel
        try {
            await Promise.all([
                loadIdentityNFT(address),
                loadResonanceScore(address),
                loadInteractionHistory(address),
                loadBlockchainHealth()
            ]);

            console.log('✅ [BlockchainDashboard] All blockchain data loaded successfully!');
        } catch (error) {
            console.error('❌ [BlockchainDashboard] Error loading blockchain data:', error);
        }
    }

    // ==================== PUBLIC API ====================

    return {
        loadBlockchainData: loadBlockchainData,
        loadIdentityNFT: loadIdentityNFT,
        loadResonanceScore: loadResonanceScore,
        loadInteractionHistory: loadInteractionHistory,
        loadBlockchainHealth: loadBlockchainHealth
    };

})();

console.log('✅ [BlockchainDashboard] Module loaded successfully!');
console.log('[BlockchainDashboard] Public API:', Object.keys(window.BlockchainDashboard));
