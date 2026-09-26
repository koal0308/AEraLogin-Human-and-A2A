/**
 * 📊 AEraLogIn Analytics Module
 * 
 * Plausible Analytics Integration (GDPR-compliant, no cookies)
 * https://plausible.io
 * 
 * Usage:
 *   - Automatically tracks page views
 *   - Call AEraAnalytics.trackEvent('EventName', {props}) for custom events
 * 
 * © 2025 VEra-Resonance Project
 */

(function() {
    'use strict';
    
    // ===== CONFIGURATION =====
    const PLAUSIBLE_SCRIPT_URL = 'https://plausible.io/js/pa-M88QuraNbHkTcRCfrPSJ4.js';
    
    // Set to true when you have a Plausible account
    const ANALYTICS_ENABLED = true;
    
    // ===== LOAD PLAUSIBLE SCRIPT =====
    if (ANALYTICS_ENABLED && !document.querySelector('script[src*="plausible.io"]')) {
        // Load the main Plausible script (async as recommended by Plausible)
        const script = document.createElement('script');
        script.async = true;
        script.src = PLAUSIBLE_SCRIPT_URL;
        document.head.appendChild(script);
        
        // Initialize Plausible queue (as per official snippet)
        window.plausible = window.plausible || function() {
            (window.plausible.q = window.plausible.q || []).push(arguments);
        };
        window.plausible.init = window.plausible.init || function(i) {
            window.plausible.o = i || {};
        };
        window.plausible.init();
        
        console.log('📊 Plausible Analytics loaded (Custom Script)');
    }
    
    // ===== CUSTOM EVENT TRACKING =====
    window.AEraAnalytics = {
        /**
         * Track a custom event
         * @param {string} eventName - Name of the event (e.g., 'Wallet Connect', 'NFT Mint')
         * @param {object} props - Optional properties (e.g., {platform: 'telegram'})
         */
        trackEvent: function(eventName, props = {}) {
            if (!ANALYTICS_ENABLED) {
                console.log('📊 [Analytics Disabled] Would track:', eventName, props);
                return;
            }
            
            // Plausible custom events
            if (typeof window.plausible !== 'undefined') {
                window.plausible(eventName, { props: props });
                console.log('📊 Event tracked:', eventName, props);
            } else {
                // Queue event if Plausible not loaded yet
                window.plausible = window.plausible || function() {
                    (window.plausible.q = window.plausible.q || []).push(arguments);
                };
                window.plausible(eventName, { props: props });
                console.log('📊 Event queued:', eventName, props);
            }
        },
        
        // ===== PRE-DEFINED EVENTS =====
        
        /**
         * Track wallet connection
         * @param {string} address - Wallet address (truncated for privacy)
         */
        walletConnect: function(address) {
            this.trackEvent('Wallet Connect', {
                address_prefix: address ? address.substring(0, 6) : 'unknown'
            });
        },
        
        /**
         * Track wallet disconnection
         */
        walletDisconnect: function() {
            this.trackEvent('Wallet Disconnect');
        },
        
        /**
         * Track NFT mint
         * @param {string} status - 'started', 'success', 'failed'
         * @param {string} tokenId - Token ID if successful
         */
        nftMint: function(status, tokenId = null) {
            const props = { status: status };
            if (tokenId) props.token_id = tokenId;
            this.trackEvent('NFT Mint', props);
        },
        
        /**
         * Track gate access attempt
         * @param {string} platform - 'telegram', 'discord', etc.
         * @param {string} result - 'granted', 'denied', 'error'
         * @param {number} score - User's resonance score
         */
        gateAccess: function(platform, result, score = null) {
            const props = { platform: platform, result: result };
            if (score) props.score = score;
            this.trackEvent('Gate Access', props);
        },
        
        /**
         * Track follow action
         * @param {string} platform - Source platform
         * @param {string} result - 'confirmed', 'pending', 'error'
         */
        followAction: function(platform, result) {
            this.trackEvent('Follow Action', {
                platform: platform,
                result: result
            });
        },
        
        /**
         * Track signature request
         * @param {string} type - 'dashboard', 'verify', 'delete'
         * @param {string} result - 'signed', 'rejected', 'error'
         */
        signatureRequest: function(type, result) {
            this.trackEvent('Signature Request', {
                type: type,
                result: result
            });
        },
        
        /**
         * Track blockchain sync
         * @param {string} type - 'score', 'nft', 'interaction'
         * @param {string} result - 'success', 'failed', 'pending'
         */
        blockchainSync: function(type, result) {
            this.trackEvent('Blockchain Sync', {
                type: type,
                result: result
            });
        },
        
        /**
         * Track gate configuration
         * @param {string} platform - 'telegram', 'discord'
         * @param {string} securityLevel - 'high', 'low'
         */
        gateConfig: function(platform, securityLevel) {
            this.trackEvent('Gate Config', {
                platform: platform,
                security: securityLevel
            });
        },
        
        /**
         * Track error
         * @param {string} context - Where the error occurred
         * @param {string} message - Error message (truncated)
         */
        trackError: function(context, message) {
            this.trackEvent('Error', {
                context: context,
                message: message ? message.substring(0, 50) : 'unknown'
            });
        }
    };
    
    // ===== AUTO-TRACK PAGE TYPE =====
    document.addEventListener('DOMContentLoaded', function() {
        const path = window.location.pathname;
        let pageType = 'other';
        
        if (path === '/' || path === '/index.html') pageType = 'landing';
        else if (path.includes('dashboard')) pageType = 'dashboard';
        else if (path.includes('follow')) pageType = 'follow';
        else if (path.includes('join-telegram') || path.includes('join-discord')) pageType = 'gate';
        else if (path.includes('gate-setup')) pageType = 'gate-setup';
        else if (path.includes('admin')) pageType = 'admin';
        else if (path.includes('privacy')) pageType = 'privacy';
        else if (path.includes('sdk') || path.includes('developer')) pageType = 'docs';
        
        // Track page type as a property (not a separate event)
        console.log('📊 Page type:', pageType);
    });
    
})();
