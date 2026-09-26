"""
AEra Gate - Python/Flask Middleware

Server-side protection for Python web applications.
Compatible with Flask, FastAPI, Django, and other frameworks.

Flask Usage:
    from aera_middleware import AEraGate, aera_required
    
    aera = AEraGate(
        client_id='your-client-id',
        client_secret='your-client-secret'
    )
    
    @app.route('/protected')
    @aera_required(aera)
    def protected_page():
        user = request.aera_user
        return f"Welcome, {user['wallet']}"

FastAPI Usage:
    from aera_middleware import AEraGate, get_aera_user
    
    aera = AEraGate(
        client_id='your-client-id',
        client_secret='your-client-secret'
    )
    
    @app.get('/protected')
    async def protected_page(aera_user: dict = Depends(aera.fastapi_dependency)):
        return {"wallet": aera_user["wallet"]}

Django Usage:
    # In middleware.py
    from aera_middleware import AEraGate
    
    class AEraMiddleware:
        def __init__(self, get_response):
            self.get_response = get_response
            self.aera = AEraGate(
                client_id=settings.AERA_CLIENT_ID,
                client_secret=settings.AERA_CLIENT_SECRET
            )
        
        def __call__(self, request):
            request.aera_user = self.aera.verify_request(request)
            return self.get_response(request)
"""

import os
import hmac
import hashlib
import secrets
import time
from functools import wraps
from typing import Optional, Dict, Any, Callable
from urllib.parse import urlencode

try:
    import requests
except ImportError:
    requests = None

try:
    import httpx
except ImportError:
    httpx = None


class AEraGate:
    """
    AEra Gate authentication handler for Python applications.
    """
    
    def __init__(
        self,
        client_id: str,
        client_secret: str,
        base_url: str = 'https://aeralogin.com',
        session_name: str = 'aera_session',
        callback_path: str = '/auth/aera/callback',
        require_nft: bool = True,
        min_score: int = 0,
        cache_ttl: int = 300  # 5 minutes
    ):
        """
        Initialize AEra Gate.
        
        Args:
            client_id: Your AEra client ID
            client_secret: Your AEra client secret
            base_url: AEra API base URL
            session_name: Session key name for storing token
            callback_path: OAuth callback path
            require_nft: Require AEra Identity NFT
            min_score: Minimum required resonance score
            cache_ttl: Token verification cache TTL in seconds
        """
        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = base_url.rstrip('/')
        self.session_name = session_name
        self.callback_path = callback_path
        self.require_nft = require_nft
        self.min_score = min_score
        self.cache_ttl = cache_ttl
        
        # Token verification cache
        self._cache: Dict[str, Dict[str, Any]] = {}
    
    def _http_client(self):
        """Get HTTP client (prefers httpx for async support)."""
        if httpx:
            return httpx.Client(timeout=10)
        elif requests:
            return requests
        else:
            raise RuntimeError("No HTTP client available. Install 'requests' or 'httpx'.")
    
    def _make_request(self, method: str, url: str, **kwargs) -> Dict[str, Any]:
        """Make HTTP request and return JSON response."""
        if httpx:
            with httpx.Client(timeout=10) as client:
                response = getattr(client, method)(url, **kwargs)
                response.raise_for_status()
                return response.json()
        elif requests:
            response = getattr(requests, method)(url, timeout=10, **kwargs)
            response.raise_for_status()
            return response.json()
        else:
            raise RuntimeError("No HTTP client available.")
    
    async def _make_request_async(self, method: str, url: str, **kwargs) -> Dict[str, Any]:
        """Make async HTTP request and return JSON response."""
        if httpx:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await getattr(client, method)(url, **kwargs)
                response.raise_for_status()
                return response.json()
        else:
            # Fallback to sync
            return self._make_request(method, url, **kwargs)
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Verify access token with AEra API.
        
        Args:
            token: Access token to verify
            
        Returns:
            User data dict if valid, None otherwise
        """
        # Check cache
        cache_key = hashlib.sha256(token.encode()).hexdigest()[:16]
        cached = self._cache.get(cache_key)
        if cached and cached['expires'] > time.time():
            return cached['data']
        
        try:
            data = self._make_request(
                'post',
                f'{self.base_url}/api/v1/verify',
                headers={
                    'Authorization': f'Bearer {token}',
                    'Content-Type': 'application/json'
                }
            )
            
            if not data.get('valid'):
                return None
            
            user_data = {
                'wallet': data.get('wallet'),
                'score': data.get('score', 0),
                'has_nft': data.get('has_nft', False),
                'token': token
            }
            
            # Cache result
            self._cache[cache_key] = {
                'data': user_data,
                'expires': time.time() + self.cache_ttl
            }
            
            return user_data
            
        except Exception as e:
            print(f"AEra verification error: {e}")
            return None
    
    async def verify_token_async(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Async version of verify_token.
        """
        cache_key = hashlib.sha256(token.encode()).hexdigest()[:16]
        cached = self._cache.get(cache_key)
        if cached and cached['expires'] > time.time():
            return cached['data']
        
        try:
            data = await self._make_request_async(
                'post',
                f'{self.base_url}/api/v1/verify',
                headers={
                    'Authorization': f'Bearer {token}',
                    'Content-Type': 'application/json'
                }
            )
            
            if not data.get('valid'):
                return None
            
            user_data = {
                'wallet': data.get('wallet'),
                'score': data.get('score', 0),
                'has_nft': data.get('has_nft', False),
                'token': token
            }
            
            self._cache[cache_key] = {
                'data': user_data,
                'expires': time.time() + self.cache_ttl
            }
            
            return user_data
            
        except Exception as e:
            print(f"AEra verification error: {e}")
            return None
    
    def check_requirements(self, user: Dict[str, Any]) -> tuple[bool, str]:
        """
        Check if user meets authentication requirements.
        
        Args:
            user: User data dict
            
        Returns:
            Tuple of (passes, error_message)
        """
        if self.require_nft and not user.get('has_nft'):
            return False, 'AEra Identity NFT required'
        
        if self.min_score > 0 and user.get('score', 0) < self.min_score:
            return False, f'Minimum score of {self.min_score} required (you have {user.get("score", 0)})'
        
        return True, ''
    
    def get_login_url(self, redirect_uri: str, state: Optional[str] = None) -> str:
        """
        Get OAuth login URL.
        
        Args:
            redirect_uri: OAuth callback URL
            state: Optional state parameter
            
        Returns:
            Login URL string
        """
        if state is None:
            state = secrets.token_urlsafe(32)
        
        params = urlencode({
            'client_id': self.client_id,
            'redirect_uri': redirect_uri,
            'response_type': 'code',
            'state': state
        })
        
        return f'{self.base_url}/oauth/authorize?{params}'
    
    def exchange_code(self, code: str, redirect_uri: str) -> Dict[str, Any]:
        """
        Exchange authorization code for access token.
        
        Args:
            code: Authorization code from callback
            redirect_uri: Same redirect URI used in authorization
            
        Returns:
            Token response dict
        """
        return self._make_request(
            'post',
            f'{self.base_url}/oauth/token',
            json={
                'grant_type': 'authorization_code',
                'code': code,
                'redirect_uri': redirect_uri,
                'client_id': self.client_id,
                'client_secret': self.client_secret
            }
        )
    
    async def exchange_code_async(self, code: str, redirect_uri: str) -> Dict[str, Any]:
        """
        Async version of exchange_code.
        """
        return await self._make_request_async(
            'post',
            f'{self.base_url}/oauth/token',
            json={
                'grant_type': 'authorization_code',
                'code': code,
                'redirect_uri': redirect_uri,
                'client_id': self.client_id,
                'client_secret': self.client_secret
            }
        )
    
    def verify_nft(self, access_token: str) -> Dict[str, Any]:
        """
        Verify NFT ownership with client credentials.
        
        Args:
            access_token: User's access token
            
        Returns:
            Verification result dict
        """
        return self._make_request(
            'post',
            f'{self.base_url}/api/oauth/verify-nft',
            json={
                'access_token': access_token,
                'client_id': self.client_id,
                'client_secret': self.client_secret
            }
        )
    
    # ===================
    # Flask Integration
    # ===================
    
    def flask_init_app(self, app):
        """
        Initialize Flask app with AEra routes.
        
        Args:
            app: Flask application instance
        """
        from flask import session, redirect, request, url_for, jsonify
        
        @app.route('/auth/aera/login')
        def aera_login():
            state = secrets.token_urlsafe(32)
            session['aera_state'] = state
            session['aera_return_to'] = request.args.get('next', '/')
            
            redirect_uri = url_for('aera_callback', _external=True)
            return redirect(self.get_login_url(redirect_uri, state))
        
        @app.route(self.callback_path)
        def aera_callback():
            code = request.args.get('code')
            state = request.args.get('state')
            error = request.args.get('error')
            
            if error:
                return jsonify({'error': error}), 400
            
            if state != session.get('aera_state'):
                return jsonify({'error': 'Invalid state'}), 400
            
            if not code:
                return jsonify({'error': 'No code'}), 400
            
            try:
                redirect_uri = url_for('aera_callback', _external=True)
                token_data = self.exchange_code(code, redirect_uri)
                
                if 'error' in token_data:
                    return jsonify(token_data), 400
                
                session[self.session_name] = token_data['access_token']
                return_to = session.pop('aera_return_to', '/')
                session.pop('aera_state', None)
                
                return redirect(return_to)
                
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @app.route('/auth/aera/logout')
        def aera_logout():
            session.pop(self.session_name, None)
            return redirect('/')
    
    def flask_get_user(self):
        """Get current user in Flask context."""
        from flask import session
        token = session.get(self.session_name)
        if not token:
            return None
        return self.verify_token(token)
    
    # ===================
    # FastAPI Integration
    # ===================
    
    async def fastapi_dependency(self, request):
        """
        FastAPI dependency for authentication.
        
        Usage:
            @app.get('/protected')
            async def protected(user: dict = Depends(aera.fastapi_dependency)):
                return {"wallet": user["wallet"]}
        """
        from fastapi import HTTPException
        
        # Try cookie first, then Authorization header
        token = request.cookies.get(self.session_name)
        if not token:
            auth_header = request.headers.get('Authorization', '')
            if auth_header.startswith('Bearer '):
                token = auth_header[7:]
        
        if not token:
            raise HTTPException(status_code=401, detail='Not authenticated')
        
        user = await self.verify_token_async(token)
        if not user:
            raise HTTPException(status_code=401, detail='Invalid token')
        
        passes, error = self.check_requirements(user)
        if not passes:
            raise HTTPException(status_code=403, detail=error)
        
        return user


# ===================
# Flask Decorator
# ===================

def aera_required(aera: AEraGate, min_score: int = 0, require_nft: bool = True):
    """
    Flask decorator to protect routes.
    
    Args:
        aera: AEraGate instance
        min_score: Minimum required score (overrides instance setting)
        require_nft: Require NFT (overrides instance setting)
    
    Usage:
        @app.route('/protected')
        @aera_required(aera)
        def protected():
            return f"Hello, {request.aera_user['wallet']}"
    """
    def decorator(f: Callable):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            from flask import session, redirect, url_for, request, jsonify
            
            token = session.get(aera.session_name)
            if not token:
                if request.is_json:
                    return jsonify({'error': 'Authentication required'}), 401
                return redirect(url_for('aera_login', next=request.url))
            
            user = aera.verify_token(token)
            if not user:
                session.pop(aera.session_name, None)
                if request.is_json:
                    return jsonify({'error': 'Invalid session'}), 401
                return redirect(url_for('aera_login', next=request.url))
            
            # Check requirements
            if require_nft and not user.get('has_nft'):
                return jsonify({'error': 'AEra Identity NFT required'}), 403
            
            if min_score > 0 and user.get('score', 0) < min_score:
                return jsonify({
                    'error': 'Insufficient score',
                    'required': min_score,
                    'actual': user.get('score', 0)
                }), 403
            
            request.aera_user = user
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator


# ===================
# Django Integration
# ===================

class AEraDjangoMiddleware:
    """
    Django middleware for AEra authentication.
    
    Add to MIDDLEWARE in settings.py:
        'aera_middleware.AEraDjangoMiddleware'
    
    Configure in settings.py:
        AERA_CLIENT_ID = 'your-client-id'
        AERA_CLIENT_SECRET = 'your-client-secret'
        AERA_BASE_URL = 'https://aeralogin.com'  # optional
        AERA_REQUIRE_NFT = True  # optional
        AERA_MIN_SCORE = 0  # optional
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        
        # Import Django settings
        try:
            from django.conf import settings
            
            self.aera = AEraGate(
                client_id=getattr(settings, 'AERA_CLIENT_ID', ''),
                client_secret=getattr(settings, 'AERA_CLIENT_SECRET', ''),
                base_url=getattr(settings, 'AERA_BASE_URL', 'https://aeralogin.com'),
                require_nft=getattr(settings, 'AERA_REQUIRE_NFT', True),
                min_score=getattr(settings, 'AERA_MIN_SCORE', 0)
            )
        except Exception:
            self.aera = None
    
    def __call__(self, request):
        if self.aera:
            token = request.session.get(self.aera.session_name)
            if token:
                user = self.aera.verify_token(token)
                request.aera_user = user
            else:
                request.aera_user = None
        
        return self.get_response(request)


def aera_login_required(view_func=None, min_score=0, require_nft=True):
    """
    Django decorator to protect views.
    
    Usage:
        @aera_login_required
        def protected_view(request):
            return HttpResponse(f"Hello, {request.aera_user['wallet']}")
        
        @aera_login_required(min_score=100)
        def high_score_view(request):
            return HttpResponse("You have a high score!")
    """
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            from django.http import JsonResponse, HttpResponseRedirect
            
            if not hasattr(request, 'aera_user') or not request.aera_user:
                if request.content_type == 'application/json':
                    return JsonResponse({'error': 'Authentication required'}, status=401)
                return HttpResponseRedirect(f'/auth/aera/login?next={request.path}')
            
            user = request.aera_user
            
            if require_nft and not user.get('has_nft'):
                return JsonResponse({'error': 'AEra Identity NFT required'}, status=403)
            
            if min_score > 0 and user.get('score', 0) < min_score:
                return JsonResponse({
                    'error': 'Insufficient score',
                    'required': min_score,
                    'actual': user.get('score', 0)
                }, status=403)
            
            return view_func(request, *args, **kwargs)
        
        return _wrapped_view
    
    if view_func:
        return decorator(view_func)
    return decorator


# ===================
# Example Usage
# ===================

if __name__ == '__main__':
    # Example: Flask app
    print("""
    === AEra Gate Python Middleware ===
    
    Flask Example:
    --------------
    from flask import Flask
    from aera_middleware import AEraGate, aera_required
    
    app = Flask(__name__)
    app.secret_key = 'your-secret-key'
    
    aera = AEraGate(
        client_id='your-client-id',
        client_secret='your-client-secret'
    )
    aera.flask_init_app(app)
    
    @app.route('/protected')
    @aera_required(aera)
    def protected():
        from flask import request
        return f"Hello, {request.aera_user['wallet']}"
    
    FastAPI Example:
    ----------------
    from fastapi import FastAPI, Depends
    from aera_middleware import AEraGate
    
    app = FastAPI()
    aera = AEraGate(
        client_id='your-client-id',
        client_secret='your-client-secret'
    )
    
    @app.get('/protected')
    async def protected(user: dict = Depends(aera.fastapi_dependency)):
        return {"wallet": user["wallet"], "score": user["score"]}
    
    Django Example:
    ---------------
    # settings.py
    AERA_CLIENT_ID = 'your-client-id'
    AERA_CLIENT_SECRET = 'your-client-secret'
    MIDDLEWARE = [
        # ...
        'aera_middleware.AEraDjangoMiddleware',
    ]
    
    # views.py
    from aera_middleware import aera_login_required
    
    @aera_login_required
    def protected_view(request):
        return HttpResponse(f"Hello, {request.aera_user['wallet']}")
    """)
