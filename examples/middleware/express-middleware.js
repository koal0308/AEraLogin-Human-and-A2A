/**
 * AEra Gate - Express.js Middleware
 * 
 * Server-side protection for Express.js applications.
 * 
 * Usage:
 *   const { aeraAuth, aeraProtect } = require('./aera-middleware');
 *   
 *   app.use(aeraAuth({
 *     clientId: 'your_client_id',
 *     clientSecret: 'your_client_secret'
 *   }));
 *   
 *   app.get('/protected', aeraProtect({ minScore: 20 }), (req, res) => {
 *     res.json({ wallet: req.aeraUser.wallet });
 *   });
 */

const https = require('https');
const http = require('http');

const AERA_API_BASE = process.env.AERA_API_BASE || 'https://aeralogin.com';

/**
 * Verify AEra session token with the API
 */
async function verifyToken(token) {
    return new Promise((resolve, reject) => {
        const url = new URL(`${AERA_API_BASE}/api/v1/verify`);
        const isHttps = url.protocol === 'https:';
        const client = isHttps ? https : http;
        
        const options = {
            hostname: url.hostname,
            port: url.port || (isHttps ? 443 : 80),
            path: url.pathname,
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            }
        };
        
        const req = client.request(options, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try {
                    resolve(JSON.parse(data));
                } catch (e) {
                    reject(new Error('Invalid API response'));
                }
            });
        });
        
        req.on('error', reject);
        req.end();
    });
}

/**
 * Exchange authorization code for access token
 */
async function exchangeCode(code, redirectUri, clientId, clientSecret) {
    return new Promise((resolve, reject) => {
        const url = new URL(`${AERA_API_BASE}/oauth/token`);
        const isHttps = url.protocol === 'https:';
        const client = isHttps ? https : http;
        
        const body = JSON.stringify({
            grant_type: 'authorization_code',
            code,
            redirect_uri: redirectUri,
            client_id: clientId,
            client_secret: clientSecret
        });
        
        const options = {
            hostname: url.hostname,
            port: url.port || (isHttps ? 443 : 80),
            path: url.pathname,
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(body)
            }
        };
        
        const req = client.request(options, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try {
                    resolve(JSON.parse(data));
                } catch (e) {
                    reject(new Error('Invalid API response'));
                }
            });
        });
        
        req.on('error', reject);
        req.write(body);
        req.end();
    });
}

/**
 * Main authentication middleware
 * Handles OAuth callback and session management
 */
function aeraAuth(options = {}) {
    const { 
        clientId, 
        clientSecret, 
        cookieName = 'aera_session',
        cookieMaxAge = 24 * 60 * 60 * 1000, // 24 hours
        loginPath = '/auth/aera/login',
        callbackPath = '/auth/aera/callback'
    } = options;
    
    if (!clientId || !clientSecret) {
        throw new Error('AEra Auth: clientId and clientSecret are required');
    }
    
    return async (req, res, next) => {
        // Handle login redirect
        if (req.path === loginPath) {
            const redirectUri = `${req.protocol}://${req.get('host')}${callbackPath}`;
            const state = require('crypto').randomBytes(16).toString('hex');
            
            // Store state in session or cookie for CSRF validation
            res.cookie('aera_state', state, { httpOnly: true, maxAge: 600000 }); // 10 min
            
            const authUrl = new URL(`${AERA_API_BASE}/oauth/authorize`);
            authUrl.searchParams.set('client_id', clientId);
            authUrl.searchParams.set('redirect_uri', redirectUri);
            authUrl.searchParams.set('response_type', 'code');
            authUrl.searchParams.set('state', state);
            
            return res.redirect(authUrl.toString());
        }
        
        // Handle OAuth callback
        if (req.path === callbackPath) {
            const { code, state, error } = req.query;
            
            if (error) {
                return res.status(400).json({ error: 'Authorization failed', details: error });
            }
            
            // Validate state
            const savedState = req.cookies?.aera_state;
            if (state && savedState && state !== savedState) {
                return res.status(400).json({ error: 'Invalid state parameter' });
            }
            res.clearCookie('aera_state');
            
            if (!code) {
                return res.status(400).json({ error: 'No authorization code' });
            }
            
            try {
                const redirectUri = `${req.protocol}://${req.get('host')}${callbackPath}`;
                const tokenData = await exchangeCode(code, redirectUri, clientId, clientSecret);
                
                if (tokenData.error) {
                    return res.status(400).json({ error: tokenData.error, details: tokenData.error_description });
                }
                
                // Set session cookie
                res.cookie(cookieName, tokenData.access_token, {
                    httpOnly: true,
                    secure: req.protocol === 'https',
                    sameSite: 'lax',
                    maxAge: cookieMaxAge
                });
                
                // Redirect to original destination or home
                const returnTo = req.cookies?.aera_return_to || '/';
                res.clearCookie('aera_return_to');
                return res.redirect(returnTo);
                
            } catch (err) {
                console.error('AEra OAuth error:', err);
                return res.status(500).json({ error: 'Token exchange failed' });
            }
        }
        
        // Check for existing session
        const token = req.cookies?.[cookieName];
        if (token) {
            try {
                const userData = await verifyToken(token);
                if (userData.valid) {
                    req.aeraUser = {
                        wallet: userData.wallet,
                        score: userData.score,
                        hasNFT: userData.has_nft,
                        expiresAt: userData.expires_at
                    };
                }
            } catch (err) {
                console.error('AEra token verification error:', err);
                // Clear invalid token
                res.clearCookie(cookieName);
            }
        }
        
        next();
    };
}

/**
 * Protection middleware - requires authentication
 */
function aeraProtect(options = {}) {
    const { 
        minScore = 0, 
        requireNFT = true,
        onDeny = null 
    } = options;
    
    return (req, res, next) => {
        // Check if user is authenticated
        if (!req.aeraUser) {
            if (onDeny) {
                return onDeny(req, res, { reason: 'not_authenticated' });
            }
            
            // Store return URL and redirect to login
            res.cookie('aera_return_to', req.originalUrl, { httpOnly: true, maxAge: 600000 });
            return res.redirect('/auth/aera/login');
        }
        
        // Check NFT requirement
        if (requireNFT && !req.aeraUser.hasNFT) {
            if (onDeny) {
                return onDeny(req, res, { reason: 'nft_required', user: req.aeraUser });
            }
            return res.status(403).json({ 
                error: 'NFT required', 
                message: 'An AEra Identity NFT is required to access this resource' 
            });
        }
        
        // Check score requirement
        if (minScore > 0 && req.aeraUser.score < minScore) {
            if (onDeny) {
                return onDeny(req, res, { 
                    reason: 'score_too_low', 
                    required: minScore, 
                    actual: req.aeraUser.score,
                    user: req.aeraUser 
                });
            }
            return res.status(403).json({ 
                error: 'Score too low', 
                message: `Minimum Resonance Score of ${minScore} required. Your score: ${req.aeraUser.score}` 
            });
        }
        
        next();
    };
}

/**
 * Logout middleware
 */
function aeraLogout(options = {}) {
    const { cookieName = 'aera_session', redirectTo = '/' } = options;
    
    return (req, res) => {
        res.clearCookie(cookieName);
        res.redirect(redirectTo);
    };
}

module.exports = {
    aeraAuth,
    aeraProtect,
    aeraLogout,
    verifyToken,
    exchangeCode,
    AERA_API_BASE
};
