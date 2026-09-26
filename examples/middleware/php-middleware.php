<?php
/**
 * AEra Gate - PHP Middleware
 * 
 * Server-side protection for PHP applications.
 * Compatible with vanilla PHP, Laravel, Symfony, and other frameworks.
 * 
 * Basic Usage:
 *   require_once 'aera-middleware.php';
 *   
 *   $aera = new AEraGate([
 *       'client_id' => 'your-client-id',
 *       'client_secret' => 'your-client-secret'
 *   ]);
 *   
 *   // Protect a page
 *   if (!$aera->checkAuth()) {
 *       $aera->redirectToLogin();
 *       exit;
 *   }
 *   
 *   // Get user data
 *   $user = $aera->getUser();
 *   echo "Welcome, " . $user['wallet'];
 * 
 * Laravel Usage:
 *   // In App\Http\Middleware\AEraAuth.php
 *   public function handle($request, Closure $next) {
 *       $aera = app('aera');
 *       if (!$aera->checkAuth()) {
 *           return redirect($aera->getLoginUrl());
 *       }
 *       $request->attributes->set('aera_user', $aera->getUser());
 *       return $next($request);
 *   }
 */

class AEraGate {
    private $config;
    private $user = null;
    private $baseUrl;
    
    /**
     * Initialize AEra Gate
     * 
     * @param array $config Configuration options
     *   - client_id: Your AEra client ID
     *   - client_secret: Your AEra client secret
     *   - base_url: AEra API base URL (default: https://aeralogin.com)
     *   - session_name: Session key name (default: aera_session)
     *   - callback_path: OAuth callback path (default: /auth/aera/callback)
     *   - require_nft: Require AEra Identity NFT (default: true)
     *   - min_score: Minimum required score (default: 0)
     */
    public function __construct(array $config) {
        $this->config = array_merge([
            'base_url' => 'https://aeralogin.com',
            'session_name' => 'aera_session',
            'callback_path' => '/auth/aera/callback',
            'require_nft' => true,
            'min_score' => 0
        ], $config);
        
        $this->baseUrl = rtrim($this->config['base_url'], '/');
        
        // Start session if not started
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
    }
    
    /**
     * Check if user is authenticated
     * 
     * @return bool True if authenticated
     */
    public function checkAuth(): bool {
        $token = $_SESSION[$this->config['session_name']] ?? null;
        
        if (!$token) {
            return false;
        }
        
        try {
            $userData = $this->verifyToken($token);
            
            if (!$userData || !($userData['valid'] ?? false)) {
                $this->clearSession();
                return false;
            }
            
            // Check NFT requirement
            if ($this->config['require_nft'] && !($userData['has_nft'] ?? false)) {
                return false;
            }
            
            // Check minimum score
            if ($this->config['min_score'] > 0 && ($userData['score'] ?? 0) < $this->config['min_score']) {
                return false;
            }
            
            $this->user = [
                'wallet' => $userData['wallet'],
                'score' => $userData['score'] ?? 0,
                'has_nft' => $userData['has_nft'] ?? false,
                'token' => $token
            ];
            
            return true;
            
        } catch (Exception $e) {
            error_log('AEra auth error: ' . $e->getMessage());
            $this->clearSession();
            return false;
        }
    }
    
    /**
     * Get authenticated user data
     * 
     * @return array|null User data or null if not authenticated
     */
    public function getUser(): ?array {
        return $this->user;
    }
    
    /**
     * Get login URL
     * 
     * @param string|null $returnTo URL to return to after login
     * @return string Login URL
     */
    public function getLoginUrl(?string $returnTo = null): string {
        $state = bin2hex(random_bytes(16));
        $_SESSION['aera_state'] = $state;
        
        if ($returnTo) {
            $_SESSION['aera_return_to'] = $returnTo;
        }
        
        $redirectUri = $this->getCallbackUrl();
        
        $params = http_build_query([
            'client_id' => $this->config['client_id'],
            'redirect_uri' => $redirectUri,
            'response_type' => 'code',
            'state' => $state
        ]);
        
        return $this->baseUrl . '/oauth/authorize?' . $params;
    }
    
    /**
     * Redirect to AEra login
     * 
     * @param string|null $returnTo URL to return to after login
     */
    public function redirectToLogin(?string $returnTo = null): void {
        $url = $this->getLoginUrl($returnTo ?? $_SERVER['REQUEST_URI']);
        header('Location: ' . $url);
        exit;
    }
    
    /**
     * Handle OAuth callback
     * 
     * @return array Result with 'success' boolean and 'redirect' or 'error'
     */
    public function handleCallback(): array {
        $code = $_GET['code'] ?? null;
        $state = $_GET['state'] ?? null;
        $error = $_GET['error'] ?? null;
        
        if ($error) {
            return [
                'success' => false,
                'error' => 'Authorization failed: ' . $error
            ];
        }
        
        // Verify state
        $savedState = $_SESSION['aera_state'] ?? null;
        if ($state && $savedState && $state !== $savedState) {
            return [
                'success' => false,
                'error' => 'Invalid state parameter'
            ];
        }
        
        if (!$code) {
            return [
                'success' => false,
                'error' => 'No authorization code received'
            ];
        }
        
        try {
            $tokenData = $this->exchangeCode($code);
            
            if (isset($tokenData['error'])) {
                return [
                    'success' => false,
                    'error' => $tokenData['error']
                ];
            }
            
            // Store token in session
            $_SESSION[$this->config['session_name']] = $tokenData['access_token'];
            
            // Get return URL
            $returnTo = $_SESSION['aera_return_to'] ?? '/';
            
            // Clean up
            unset($_SESSION['aera_state']);
            unset($_SESSION['aera_return_to']);
            
            return [
                'success' => true,
                'redirect' => $returnTo
            ];
            
        } catch (Exception $e) {
            return [
                'success' => false,
                'error' => 'Token exchange failed: ' . $e->getMessage()
            ];
        }
    }
    
    /**
     * Logout user
     */
    public function logout(): void {
        unset($_SESSION[$this->config['session_name']]);
        $this->user = null;
    }
    
    /**
     * Clear session data
     */
    private function clearSession(): void {
        unset($_SESSION[$this->config['session_name']]);
        unset($_SESSION['aera_state']);
        unset($_SESSION['aera_return_to']);
    }
    
    /**
     * Get callback URL
     * 
     * @return string Full callback URL
     */
    private function getCallbackUrl(): string {
        $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
        $host = $_SERVER['HTTP_HOST'];
        return $protocol . '://' . $host . $this->config['callback_path'];
    }
    
    /**
     * Verify token with AEra API
     * 
     * @param string $token Access token
     * @return array|null Response data or null on failure
     */
    private function verifyToken(string $token): ?array {
        $url = $this->baseUrl . '/api/v1/verify';
        
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_HTTPHEADER => [
                'Authorization: Bearer ' . $token,
                'Content-Type: application/json'
            ],
            CURLOPT_TIMEOUT => 10
        ]);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($httpCode !== 200) {
            return null;
        }
        
        return json_decode($response, true);
    }
    
    /**
     * Exchange authorization code for access token
     * 
     * @param string $code Authorization code
     * @return array Token response
     * @throws Exception On API error
     */
    private function exchangeCode(string $code): array {
        $url = $this->baseUrl . '/oauth/token';
        
        $data = json_encode([
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $this->getCallbackUrl(),
            'client_id' => $this->config['client_id'],
            'client_secret' => $this->config['client_secret']
        ]);
        
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $data,
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/json',
                'Content-Length: ' . strlen($data)
            ],
            CURLOPT_TIMEOUT => 10
        ]);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);
        
        if ($error) {
            throw new Exception('cURL error: ' . $error);
        }
        
        if ($httpCode !== 200) {
            throw new Exception('HTTP error: ' . $httpCode);
        }
        
        return json_decode($response, true);
    }
    
    /**
     * Verify NFT with client credentials (for API endpoints)
     * 
     * @param string $accessToken User's access token
     * @return array Verification result
     */
    public function verifyNFT(string $accessToken): array {
        $url = $this->baseUrl . '/api/oauth/verify-nft';
        
        $data = json_encode([
            'access_token' => $accessToken,
            'client_id' => $this->config['client_id'],
            'client_secret' => $this->config['client_secret']
        ]);
        
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $data,
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/json'
            ],
            CURLOPT_TIMEOUT => 10
        ]);
        
        $response = curl_exec($ch);
        curl_close($ch);
        
        return json_decode($response, true);
    }
}

/**
 * Simple function to protect a page
 * 
 * @param array $config AEra configuration
 * @param string|null $redirectOnFail Redirect URL on auth failure
 * @return array|false User data if authenticated, false otherwise
 */
function aera_protect(array $config, ?string $redirectOnFail = null) {
    $aera = new AEraGate($config);
    
    if ($aera->checkAuth()) {
        return $aera->getUser();
    }
    
    if ($redirectOnFail) {
        header('Location: ' . $redirectOnFail);
        exit;
    }
    
    $aera->redirectToLogin();
    exit;
}

/**
 * Handle OAuth callback page
 * 
 * @param array $config AEra configuration
 */
function aera_callback(array $config) {
    $aera = new AEraGate($config);
    $result = $aera->handleCallback();
    
    if ($result['success']) {
        header('Location: ' . $result['redirect']);
    } else {
        http_response_code(400);
        echo json_encode(['error' => $result['error']]);
    }
    exit;
}

// ======================
// Laravel Integration
// ======================

if (class_exists('Illuminate\Support\ServiceProvider')) {
    
    class AEraServiceProvider extends \Illuminate\Support\ServiceProvider {
        public function register() {
            $this->app->singleton('aera', function ($app) {
                return new AEraGate([
                    'client_id' => config('services.aera.client_id'),
                    'client_secret' => config('services.aera.client_secret'),
                    'base_url' => config('services.aera.base_url', 'https://aeralogin.com'),
                    'require_nft' => config('services.aera.require_nft', true),
                    'min_score' => config('services.aera.min_score', 0)
                ]);
            });
        }
    }
    
    // Example middleware for Laravel
    // Add to App\Http\Middleware\AEraAuth
    /*
    class AEraAuth {
        public function handle($request, Closure $next, $minScore = 0) {
            $aera = app('aera');
            
            if (!$aera->checkAuth()) {
                if ($request->expectsJson()) {
                    return response()->json(['error' => 'Unauthorized'], 401);
                }
                return redirect($aera->getLoginUrl($request->fullUrl()));
            }
            
            $request->attributes->set('aera_user', $aera->getUser());
            return $next($request);
        }
    }
    */
}
