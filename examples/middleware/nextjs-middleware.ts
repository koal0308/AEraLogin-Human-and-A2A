/**
 * AEra Gate - Next.js Middleware
 * 
 * Server-side protection for Next.js applications.
 * 
 * Usage in middleware.ts:
 *   import { aeraMiddleware } from './lib/aera-middleware';
 *   export default aeraMiddleware({
 *     clientId: process.env.AERA_CLIENT_ID!,
 *     clientSecret: process.env.AERA_CLIENT_SECRET!,
 *     protectedPaths: ['/dashboard', '/api/protected/*']
 *   });
 * 
 * Usage in API routes:
 *   import { getAeraUser } from './lib/aera-middleware';
 *   export async function GET(req) {
 *     const user = await getAeraUser(req);
 *     if (!user) return Response.json({ error: 'Unauthorized' }, { status: 401 });
 *     return Response.json({ wallet: user.wallet });
 *   }
 */

import { NextRequest, NextResponse } from 'next/server';

const AERA_API_BASE = process.env.AERA_API_BASE || 'https://aeralogin.com';

export interface AeraUser {
    wallet: string;
    score: number;
    hasNFT: boolean;
    expiresAt: string;
}

export interface AeraMiddlewareOptions {
    clientId: string;
    clientSecret: string;
    cookieName?: string;
    loginPath?: string;
    callbackPath?: string;
    protectedPaths?: string[];
    minScore?: number;
    requireNFT?: boolean;
}

/**
 * Verify AEra session token
 */
export async function verifyToken(token: string): Promise<{ valid: boolean; [key: string]: any }> {
    const response = await fetch(`${AERA_API_BASE}/api/v1/verify`, {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
        }
    });
    return response.json();
}

/**
 * Exchange authorization code for access token
 */
export async function exchangeCode(
    code: string, 
    redirectUri: string, 
    clientId: string, 
    clientSecret: string
): Promise<{ access_token?: string; error?: string; [key: string]: any }> {
    const response = await fetch(`${AERA_API_BASE}/oauth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            grant_type: 'authorization_code',
            code,
            redirect_uri: redirectUri,
            client_id: clientId,
            client_secret: clientSecret
        })
    });
    return response.json();
}

/**
 * Get AEra user from request cookies
 */
export async function getAeraUser(req: NextRequest, cookieName = 'aera_session'): Promise<AeraUser | null> {
    const token = req.cookies.get(cookieName)?.value;
    if (!token) return null;
    
    try {
        const userData = await verifyToken(token);
        if (!userData.valid) return null;
        
        return {
            wallet: userData.wallet,
            score: userData.score,
            hasNFT: userData.has_nft,
            expiresAt: userData.expires_at
        };
    } catch {
        return null;
    }
}

/**
 * Check if path matches any protected pattern
 */
function isProtectedPath(pathname: string, patterns: string[]): boolean {
    return patterns.some(pattern => {
        if (pattern.includes('*')) {
            const regex = new RegExp('^' + pattern.replace(/\*/g, '.*') + '$');
            return regex.test(pathname);
        }
        return pathname === pattern || pathname.startsWith(pattern + '/');
    });
}

/**
 * Main Next.js middleware
 */
export function aeraMiddleware(options: AeraMiddlewareOptions) {
    const {
        clientId,
        clientSecret,
        cookieName = 'aera_session',
        loginPath = '/auth/aera/login',
        callbackPath = '/auth/aera/callback',
        protectedPaths = [],
        minScore = 0,
        requireNFT = true
    } = options;
    
    return async function middleware(req: NextRequest) {
        const { pathname } = req.nextUrl;
        
        // Handle login redirect
        if (pathname === loginPath) {
            const redirectUri = `${req.nextUrl.origin}${callbackPath}`;
            const state = crypto.randomUUID();
            
            const authUrl = new URL(`${AERA_API_BASE}/oauth/authorize`);
            authUrl.searchParams.set('client_id', clientId);
            authUrl.searchParams.set('redirect_uri', redirectUri);
            authUrl.searchParams.set('response_type', 'code');
            authUrl.searchParams.set('state', state);
            
            const response = NextResponse.redirect(authUrl);
            response.cookies.set('aera_state', state, { httpOnly: true, maxAge: 600 });
            return response;
        }
        
        // Handle OAuth callback
        if (pathname === callbackPath) {
            const code = req.nextUrl.searchParams.get('code');
            const state = req.nextUrl.searchParams.get('state');
            const error = req.nextUrl.searchParams.get('error');
            
            if (error) {
                return NextResponse.json({ error: 'Authorization failed', details: error }, { status: 400 });
            }
            
            const savedState = req.cookies.get('aera_state')?.value;
            if (state && savedState && state !== savedState) {
                return NextResponse.json({ error: 'Invalid state' }, { status: 400 });
            }
            
            if (!code) {
                return NextResponse.json({ error: 'No authorization code' }, { status: 400 });
            }
            
            try {
                const redirectUri = `${req.nextUrl.origin}${callbackPath}`;
                const tokenData = await exchangeCode(code, redirectUri, clientId, clientSecret);
                
                if (tokenData.error) {
                    return NextResponse.json({ error: tokenData.error }, { status: 400 });
                }
                
                const returnTo = req.cookies.get('aera_return_to')?.value || '/';
                const response = NextResponse.redirect(new URL(returnTo, req.url));
                
                response.cookies.set(cookieName, tokenData.access_token!, {
                    httpOnly: true,
                    secure: req.nextUrl.protocol === 'https:',
                    sameSite: 'lax',
                    maxAge: 86400 // 24 hours
                });
                response.cookies.delete('aera_state');
                response.cookies.delete('aera_return_to');
                
                return response;
                
            } catch (err) {
                console.error('AEra OAuth error:', err);
                return NextResponse.json({ error: 'Token exchange failed' }, { status: 500 });
            }
        }
        
        // Check protected paths
        if (protectedPaths.length > 0 && isProtectedPath(pathname, protectedPaths)) {
            const user = await getAeraUser(req, cookieName);
            
            if (!user) {
                const response = NextResponse.redirect(new URL(loginPath, req.url));
                response.cookies.set('aera_return_to', pathname, { httpOnly: true, maxAge: 600 });
                return response;
            }
            
            if (requireNFT && !user.hasNFT) {
                return NextResponse.json({ 
                    error: 'NFT required',
                    message: 'An AEra Identity NFT is required'
                }, { status: 403 });
            }
            
            if (minScore > 0 && user.score < minScore) {
                return NextResponse.json({ 
                    error: 'Score too low',
                    required: minScore,
                    actual: user.score
                }, { status: 403 });
            }
        }
        
        return NextResponse.next();
    };
}

export default aeraMiddleware;
