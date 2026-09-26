/**
 * AEra Gate SDK v1.0.0
 * 
 * NFT-Gated Access for Third-Party Websites
 * https://aeralogin.com
 * 
 * @license Apache-2.0
 * © 2025 VEra-Resonance Project
 */

(function(global) {
    'use strict';

    // ============================================================================
    // CONFIGURATION
    // ============================================================================
    
    const DEFAULT_CONFIG = {
        apiBase: 'https://aeralogin.com',
        mode: 'client', // 'client' (UI only) or 'secure' (requires server-side verification)
        clientId: null,
        sessionCookieName: 'aera_session',
        debug: false
    };

    let config = { ...DEFAULT_CONFIG };
    let currentSession = null;

    // ============================================================================
    // UTILITIES
    // ============================================================================

    function log(...args) {
        if (config.debug) {
            console.log('[AEraGate]', ...args);
        }
    }

    function getCookie(name) {
        const value = `; ${document.cookie}`;
        const parts = value.split(`; ${name}=`);
        if (parts.length === 2) return parts.pop().split(';').shift();
        return null;
    }

    function setCookie(name, value, days = 1) {
        const expires = new Date(Date.now() + days * 24 * 60 * 60 * 1000).toUTCString();
        document.cookie = `${name}=${value}; expires=${expires}; path=/; SameSite=Lax${location.protocol === 'https:' ? '; Secure' : ''}`;
    }

    function deleteCookie(name) {
        document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;`;
    }

    function generateState() {
        const array = new Uint8Array(16);
        crypto.getRandomValues(array);
        return Array.from(array, b => b.toString(16).padStart(2, '0')).join('');
    }

    // ============================================================================
    // SESSION MANAGEMENT
    // ============================================================================

    async function getSession() {
        // Check for existing token in cookie
        const token = getCookie(config.sessionCookieName);
        if (!token) {
            log('No session token found');
            return null;
        }

        // In secure mode, verify with backend
        if (config.mode === 'secure') {
            try {
                const response = await fetch(`${config.apiBase}/api/v1/verify`, {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${token}`,
                        'Content-Type': 'application/json'
                    }
                });
                
                const data = await response.json();
                
                if (data.valid) {
                    currentSession = {
                        wallet: data.wallet,
                        score: data.score,
                        hasNFT: data.has_nft,
                        expiresAt: data.expires_at
                    };
                    log('Session verified:', currentSession);
                    return currentSession;
                } else {
                    log('Session invalid:', data.error);
                    deleteCookie(config.sessionCookieName);
                    return null;
                }
            } catch (error) {
                log('Session verification error:', error);
                return null;
            }
        }

        // In client mode, decode JWT without server verification
        try {
            const payload = JSON.parse(atob(token.split('.')[1]));
            
            // Check expiry
            if (payload.exp && payload.exp * 1000 < Date.now()) {
                log('Token expired');
                deleteCookie(config.sessionCookieName);
                return null;
            }

            currentSession = {
                wallet: payload.sub,
                score: payload.score,
                hasNFT: payload.has_nft,
                expiresAt: new Date(payload.exp * 1000).toISOString()
            };
            
            log('Session decoded (client mode):', currentSession);
            return currentSession;
        } catch (error) {
            log('Token decode error:', error);
            deleteCookie(config.sessionCookieName);
            return null;
        }
    }

    // ============================================================================
    // PROTECTION LOGIC
    // ============================================================================

    function createDeniedUI(element, options) {
        const container = document.createElement('div');
        container.className = 'aera-gate-denied';
        container.innerHTML = `
            <div class="aera-gate-box">
                <div class="aera-gate-icon">🔐</div>
                <div class="aera-gate-title">Access Required</div>
                <div class="aera-gate-text">
                    ${options.requireNFT ? 'Identity NFT required' : ''}
                    ${options.minScore > 0 ? `<br>Minimum Score: ${options.minScore}` : ''}
                </div>
                <button class="aera-gate-button" onclick="AEraGate.login()">
                    Continue with AEraLogIn
                </button>
            </div>
        `;
        
        // Hide original content
        element.style.display = 'none';
        element.parentNode.insertBefore(container, element);
        
        return container;
    }

    function removeDeniedUI(element) {
        const denied = element.previousSibling;
        if (denied && denied.classList && denied.classList.contains('aera-gate-denied')) {
            denied.remove();
        }
        element.style.display = '';
    }

    async function checkAccess(options) {
        const session = await getSession();
        
        if (!session) {
            return { allowed: false, reason: 'not_authenticated' };
        }

        if (options.requireNFT && !session.hasNFT) {
            return { allowed: false, reason: 'nft_required', session };
        }

        if (options.minScore && session.score < options.minScore) {
            return { allowed: false, reason: 'score_too_low', session, required: options.minScore, actual: session.score };
        }

        return { allowed: true, session };
    }

    // ============================================================================
    // PUBLIC API
    // ============================================================================

    const AEraGate = {
        /**
         * Initialize the SDK
         * @param {Object} options Configuration options
         * @param {string} options.clientId - Your OAuth client ID
         * @param {string} [options.mode='client'] - 'client' or 'secure'
         * @param {string} [options.apiBase] - API base URL
         * @param {boolean} [options.debug=false] - Enable debug logging
         */
        init: function(options = {}) {
            config = { ...DEFAULT_CONFIG, ...options };
            
            if (!config.clientId) {
                console.warn('[AEraGate] Warning: clientId not set. Login will not work.');
            }
            
            log('Initialized with config:', config);
            
            // Inject default styles
            if (!document.getElementById('aera-gate-styles')) {
                const style = document.createElement('style');
                style.id = 'aera-gate-styles';
                style.textContent = `
                    .aera-gate-denied {
                        padding: 2rem;
                        text-align: center;
                        background: linear-gradient(135deg, #050814 0%, #0a0e27 100%);
                        border-radius: 16px;
                        border: 1px solid rgba(99, 102, 241, 0.3);
                        color: #f0f4ff;
                        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
                    }
                    .aera-gate-box {
                        max-width: 400px;
                        margin: 0 auto;
                    }
                    .aera-gate-icon {
                        font-size: 3rem;
                        margin-bottom: 1rem;
                    }
                    .aera-gate-title {
                        font-size: 1.5rem;
                        font-weight: 700;
                        margin-bottom: 0.5rem;
                    }
                    .aera-gate-text {
                        color: rgba(240, 244, 255, 0.7);
                        margin-bottom: 1.5rem;
                        line-height: 1.6;
                    }
                    .aera-gate-button {
                        background: linear-gradient(135deg, #0052ff, #6366f1);
                        color: white;
                        border: none;
                        padding: 0.875rem 2rem;
                        border-radius: 10px;
                        font-size: 1rem;
                        font-weight: 600;
                        cursor: pointer;
                        transition: transform 0.2s, box-shadow 0.2s;
                    }
                    .aera-gate-button:hover {
                        transform: translateY(-2px);
                        box-shadow: 0 10px 30px rgba(0, 82, 255, 0.4);
                    }
                `;
                document.head.appendChild(style);
            }
            
            // Auto-protect elements with data-aera-protect attribute
            this.autoProtect();
        },

        /**
         * Protect content areas
         * @param {Object} options Protection options
         * @param {string} options.selector - CSS selector for elements to protect
         * @param {number} [options.minScore=0] - Minimum Resonance Score required
         * @param {boolean} [options.requireNFT=true] - Require Identity NFT
         * @param {Function} [options.onAllow] - Callback when access is granted
         * @param {Function} [options.onDeny] - Callback when access is denied
         */
        protect: async function(options = {}) {
            // Support both attribute names for flexibility
            const selector = options.selector || '[data-aera-protect], [data-aera-protected]';
            const elements = document.querySelectorAll(selector);
            
            log(`Protecting ${elements.length} elements with selector: ${selector}`);
            
            const accessResult = await checkAccess({
                minScore: options.minScore || 0,
                requireNFT: options.requireNFT !== false
            });
            
            elements.forEach(element => {
                const elemMinScore = parseInt(element.dataset.minScore) || options.minScore || 0;
                const elemRequireNFT = element.dataset.requireNft !== 'false' && options.requireNFT !== false;
                
                const elemAccess = {
                    ...accessResult,
                    allowed: accessResult.allowed && 
                             (!elemRequireNFT || accessResult.session?.hasNFT) &&
                             (accessResult.session?.score || 0) >= elemMinScore
                };
                
                if (elemAccess.allowed) {
                    log('Access granted for element');
                    removeDeniedUI(element);
                    if (options.onAllow) options.onAllow(elemAccess.session, element);
                } else {
                    log('Access denied for element:', elemAccess.reason);
                    createDeniedUI(element, { minScore: elemMinScore, requireNFT: elemRequireNFT });
                    if (options.onDeny) options.onDeny(elemAccess, element);
                }
            });
            
            return accessResult;
        },

        /**
         * Auto-protect elements marked with data-aera-protect or data-aera-protected
         */
        autoProtect: async function() {
            // Support both attribute names for flexibility
            const elements = document.querySelectorAll('[data-aera-protect], [data-aera-protected]');
            if (elements.length > 0) {
                log(`Auto-protecting ${elements.length} elements`);
                await this.protect({});
            }
        },

        /**
         * Start OAuth login flow
         * @param {Object} options Login options
         * @param {string} [options.redirectUri] - Where to redirect after login (defaults to current page)
         */
        login: function(options = {}) {
            if (!config.clientId) {
                console.error('[AEraGate] Cannot login: clientId not configured');
                return;
            }
            
            const redirectUri = options.redirectUri || window.location.href.split('?')[0];
            const state = generateState();
            
            // Store state for CSRF validation
            sessionStorage.setItem('aera_oauth_state', state);
            
            // Build authorization URL
            const authUrl = new URL(`${config.apiBase}/oauth/authorize`);
            authUrl.searchParams.set('client_id', config.clientId);
            authUrl.searchParams.set('redirect_uri', redirectUri);
            authUrl.searchParams.set('response_type', 'code');
            authUrl.searchParams.set('state', state);
            
            log('Redirecting to authorization:', authUrl.toString());
            window.location.href = authUrl.toString();
        },

        /**
         * Handle OAuth callback (call this on your redirect_uri page)
         * @returns {Promise<Object|null>} Session data or null if failed
         */
        handleCallback: async function() {
            const params = new URLSearchParams(window.location.search);
            const code = params.get('code');
            const state = params.get('state');
            const error = params.get('error');
            
            if (error) {
                log('OAuth error:', error);
                return null;
            }
            
            if (!code) {
                log('No authorization code in URL');
                return null;
            }
            
            // Validate state
            const savedState = sessionStorage.getItem('aera_oauth_state');
            if (state && savedState && state !== savedState) {
                console.error('[AEraGate] State mismatch - possible CSRF attack');
                return null;
            }
            sessionStorage.removeItem('aera_oauth_state');
            
            // Clean URL
            const cleanUrl = window.location.pathname;
            window.history.replaceState({}, document.title, cleanUrl);
            
            log('Authorization code received, token exchange should happen on server');
            
            // In client mode, we can't do token exchange (no client_secret)
            // The server should have already set the cookie via the callback endpoint
            
            return await getSession();
        },

        /**
         * Logout and clear session
         * @param {Object} [options] Logout options
         * @param {string} [options.redirectUrl] - Where to redirect after logout
         */
        logout: function(options = {}) {
            deleteCookie(config.sessionCookieName);
            currentSession = null;
            log('Session cleared');
            
            if (options.redirectUrl) {
                window.location.href = options.redirectUrl;
            } else {
                // Refresh to re-apply protection
                window.location.reload();
            }
        },

        /**
         * Get current session info
         * @returns {Promise<Object|null>} Current session or null
         */
        getSession: getSession,

        /**
         * Check if user has access
         * @param {Object} options Access requirements
         * @returns {Promise<Object>} Access result
         */
        checkAccess: checkAccess,

        /**
         * SDK Version
         */
        version: '1.0.0'
    };

    // ============================================================================
    // EXPORTS
    // ============================================================================

    // Export to global scope
    global.AEraGate = AEraGate;

    // AMD support
    if (typeof define === 'function' && define.amd) {
        define('AEraGate', [], function() { return AEraGate; });
    }

    // CommonJS support
    if (typeof module === 'object' && module.exports) {
        module.exports = AEraGate;
    }

    // Auto-initialize on DOM ready if data attributes found
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function() {
            // Check for auto-init via script data attribute
            const script = document.querySelector('script[data-aera-client-id]');
            if (script) {
                AEraGate.init({
                    clientId: script.dataset.aeraClientId,
                    mode: script.dataset.aeraMode || 'client',
                    debug: script.dataset.aeraDebug === 'true'
                });
            }
        });
    }

})(typeof window !== 'undefined' ? window : this);
