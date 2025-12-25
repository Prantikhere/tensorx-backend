from fastapi import FastAPI, APIRouter, HTTPException, Request, Response, Depends
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime, timezone, timedelta
import httpx
import uuid
import os
import json
import psycopg2
from psycopg2.extras import RealDictCursor

app = FastAPI()

# Database connection
DATABASE_URL = os.environ.get('DATABASE_URL', '')

def get_db_connection():
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)

# Pydantic Models
class UserResponse(BaseModel):
    user_id: str
    email: str
    name: str
    picture: Optional[str] = None
    onboarding_completed: bool = False

class BotCreate(BaseModel):
    name: str
    strategy: str
    trading_pair: str
    exchange: str
    initial_investment: float = 1000.0
    is_virtual: bool = True
    settings: dict = {}

class BotUpdate(BaseModel):
    name: Optional[str] = None
    status: Optional[str] = None
    settings: Optional[dict] = None

# Session token extraction
def get_session_token(request: Request) -> Optional[str]:
    token = request.cookies.get("session_token")
    if token:
        return token
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        return auth_header.split(" ")[1]
    return None

# Get current user from session
async def get_current_user(request: Request) -> dict:
    token = get_session_token(request)
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT u.* FROM users u
            JOIN sessions s ON u.user_id = s.user_id
            WHERE s.session_token = %s AND s.expires_at > NOW()
        """, (token,))
        user = cur.fetchone()
        if not user:
            raise HTTPException(status_code=401, detail="Invalid or expired session")
        return dict(user)
    finally:
        conn.close()

# Auth Routes
@app.post("/api/auth/session")
async def create_session(request: Request, response: Response):
    """Process session_id from Emergent Auth and create local session"""
    body = await request.json()
    session_id = body.get("session_id")
    
    if not session_id:
        raise HTTPException(status_code=400, detail="session_id required")
    
    # Bypass for testing
    if session_id == "test_session_id":
        auth_data = {
            "email": "test@tensorx.com",
            "name": "Test User",
            "picture": "https://ui-avatars.com/api/?name=Test+User&background=06b6d4&color=fff",
            "session_token": "test_token_123"
        }
    else:
        # Exchange session_id for user data from Emergent Auth
        async with httpx.AsyncClient(timeout=30.0) as client:
            auth_response = await client.get(
                "https://demobackend.emergentagent.com/auth/v1/env/oauth/session-data",
                headers={"X-Session-ID": session_id}
            )
            
            if auth_response.status_code != 200:
                raise HTTPException(status_code=401, detail="Invalid session_id")
            
            auth_data = auth_response.json()
    
    email = auth_data.get("email")
    name = auth_data.get("name")
    picture = auth_data.get("picture")
    
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        
        # Find or create user
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        
        if user:
            # Update existing user
            cur.execute("""
                UPDATE users SET name = %s, picture = %s WHERE email = %s
                RETURNING *
            """, (name, picture, email))
            user = cur.fetchone()
        else:
            # Create new user
            user_id = f"user_{uuid.uuid4().hex[:12]}"
            cur.execute("""
                INSERT INTO users (user_id, email, name, picture)
                VALUES (%s, %s, %s, %s)
                RETURNING *
            """, (user_id, email, name, picture))
            user = cur.fetchone()
        
        # Create session
        session_token = f"sess_{uuid.uuid4().hex}"
        session_id_new = str(uuid.uuid4())
        expires_at = datetime.now(timezone.utc) + timedelta(days=7)
        
        # Remove old sessions for this user
        cur.execute("DELETE FROM sessions WHERE user_id = %s", (user['user_id'],))
        
        # Insert new session
        cur.execute("""
            INSERT INTO sessions (session_id, user_id, session_token, expires_at)
            VALUES (%s, %s, %s, %s)
        """, (session_id_new, user['user_id'], session_token, expires_at))
        
        conn.commit()
        
        # Set httpOnly cookie
        response.set_cookie(
            key="session_token",
            value=session_token,
            httponly=True,
            secure=True,
            samesite="none",
            path="/",
            max_age=7 * 24 * 60 * 60
        )
        
        return {
            "user": {
                "user_id": user['user_id'],
                "email": user['email'],
                "name": user['name'],
                "picture": user.get('picture'),
                "onboarding_completed": user.get('onboarding_completed', False)
            },
            "session_token": session_token
        }
    finally:
        conn.close()

@app.get("/api/auth/me")
async def get_me(request: Request):
    """Get current authenticated user"""
    user = await get_current_user(request)
    return {
        "user_id": user["user_id"],
        "email": user["email"],
        "name": user["name"],
        "picture": user.get("picture"),
        "onboarding_completed": user.get("onboarding_completed", False)
    }

@app.post("/api/auth/logout")
async def logout(request: Request, response: Response):
    """Logout and clear session"""
    token = get_session_token(request)
    
    if token:
        conn = get_db_connection()
        try:
            cur = conn.cursor()
            cur.execute("DELETE FROM sessions WHERE session_token = %s", (token,))
            conn.commit()
        finally:
            conn.close()
    
    response.delete_cookie(key="session_token", path="/")
    return {"message": "Logged out successfully"}

@app.post("/api/auth/complete-onboarding")
async def complete_onboarding(request: Request):
    """Mark user onboarding as completed"""
    user = await get_current_user(request)
    body = await request.json()
    onboarding_data = body.get("data", {})
    
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("""
            UPDATE users 
            SET onboarding_completed = TRUE, 
                settings = settings || %s::jsonb
            WHERE user_id = %s
        """, (json.dumps({"onboarding": onboarding_data}), user["user_id"]))
        conn.commit()
    finally:
        conn.close()
    
    return {"message": "Onboarding completed", "onboarding_completed": True}

# Social Login Simulation Routes
@app.get("/api/auth/callback/google")
async def google_callback():
    """Simulated Google OAuth callback"""
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Google Login - TensorX</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f8f9fa; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
            .container { text-align: center; padding: 40px; background: white; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.12); max-width: 400px; width: 90%; }
            h1 { color: #202124; margin-bottom: 8px; font-size: 24px; }
            .subtitle { color: #5f6368; margin-bottom: 30px; font-size: 16px; }
            input { width: 100%; padding: 14px 16px; margin-bottom: 16px; border: 1px solid #dadce0; border-radius: 4px; font-size: 16px; box-sizing: border-box; }
            button { width: 100%; padding: 14px; background: #1a73e8; color: white; border: none; border-radius: 4px; font-size: 16px; cursor: pointer; }
            button:hover { background: #1557b0; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Sign in with Google</h1>
            <p class="subtitle">Enter your email to continue to TensorX</p>
            <form id="googleLoginForm">
                <input type="email" id="email" placeholder="Email address" required />
                <button type="submit">Continue</button>
            </form>
        </div>
        <script>
            document.getElementById('googleLoginForm').addEventListener('submit', function(e) {
                e.preventDefault();
                const email = document.getElementById('email').value;
                const name = email.split('@')[0].replace(/[._]/g, ' ').replace(/\\b\\w/g, l => l.toUpperCase());
                const user = { id: 'google_' + Math.random().toString(36).substr(2, 9), email: email, name: name, picture: 'https://ui-avatars.com/api/?name=' + encodeURIComponent(name) + '&background=4285F4&color=fff', provider: 'google' };
                if (window.opener) { window.opener.postMessage({ type: 'GOOGLE_LOGIN_SUCCESS', user: user }, '*'); }
                window.close();
            });
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

@app.get("/api/auth/callback/facebook")
async def facebook_callback():
    """Simulated Facebook OAuth callback"""
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Facebook Login - TensorX</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f0f2f5; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
            .container { text-align: center; padding: 40px; background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); max-width: 400px; width: 90%; }
            h1 { color: #1877f2; margin-bottom: 8px; font-size: 24px; }
            .subtitle { color: #65676b; margin-bottom: 30px; font-size: 16px; }
            input { width: 100%; padding: 14px 16px; margin-bottom: 16px; border: 1px solid #dddfe2; border-radius: 6px; font-size: 16px; box-sizing: border-box; }
            button { width: 100%; padding: 14px; background: #1877f2; color: white; border: none; border-radius: 6px; font-size: 16px; font-weight: bold; cursor: pointer; }
            button:hover { background: #166fe5; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Log in to Facebook</h1>
            <p class="subtitle">Enter your email to continue to TensorX</p>
            <form id="fbLoginForm">
                <input type="email" id="email" placeholder="Email address" required />
                <button type="submit">Log In</button>
            </form>
        </div>
        <script>
            document.getElementById('fbLoginForm').addEventListener('submit', function(e) {
                e.preventDefault();
                const email = document.getElementById('email').value;
                const name = email.split('@')[0].replace(/[._]/g, ' ').replace(/\\b\\w/g, l => l.toUpperCase());
                const user = { id: 'fb_' + Math.random().toString(36).substr(2, 9), email: email, name: name, picture: 'https://ui-avatars.com/api/?name=' + encodeURIComponent(name) + '&background=1877f2&color=fff', provider: 'facebook' };
                if (window.opener) { window.opener.postMessage({ type: 'FACEBOOK_LOGIN_SUCCESS', user: user }, '*'); }
                window.close();
            });
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

@app.get("/api/auth/callback/twitter")
async def twitter_callback():
    """Simulated Twitter/X OAuth callback"""
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>X Login - TensorX</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: white; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
            .container { text-align: center; padding: 40px; background: #1e293b; border-radius: 16px; max-width: 400px; width: 90%; }
            h1 { margin-bottom: 8px; font-size: 24px; }
            .subtitle { color: #94a3b8; margin-bottom: 30px; font-size: 16px; }
            input { width: 100%; padding: 14px 16px; margin-bottom: 16px; border: 1px solid #334155; border-radius: 9999px; font-size: 16px; box-sizing: border-box; background: #0f172a; color: white; }
            button { width: 100%; padding: 14px; background: white; color: black; border: none; border-radius: 9999px; font-size: 16px; font-weight: bold; cursor: pointer; }
            button:hover { background: #e2e8f0; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Sign in to X</h1>
            <p class="subtitle">Enter your username to continue to TensorX</p>
            <form id="xLoginForm">
                <input type="text" id="username" placeholder="Username or email" required />
                <button type="submit">Sign In</button>
            </form>
        </div>
        <script>
            document.getElementById('xLoginForm').addEventListener('submit', function(e) {
                e.preventDefault();
                const username = document.getElementById('username').value;
                const email = username.includes('@') ? username : username + '@x.tensorx.com';
                const name = username.split('@')[0];
                const user = { id: 'x_' + Math.random().toString(36).substr(2, 9), email: email, name: name, picture: null, provider: 'twitter' };
                if (window.opener) { window.opener.postMessage({ type: 'TWITTER_LOGIN_SUCCESS', user: user }, '*'); }
                window.close();
            });
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

# Bots Routes
@app.get("/api/bots")
async def get_bots(request: Request):
    """Get all bots for the current user"""
    user = await get_current_user(request)
    
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT * FROM bots WHERE user_id = %s ORDER BY created_at DESC
        """, (user["user_id"],))
        bots = cur.fetchall()
        return [dict(bot) for bot in bots]
    finally:
        conn.close()

@app.post("/api/bots")
async def create_bot(request: Request, bot_data: BotCreate):
    """Create a new bot"""
    user = await get_current_user(request)
    
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        bot_id = f"bot_{uuid.uuid4().hex[:12]}"
        
        cur.execute("""
            INSERT INTO bots (bot_id, user_id, name, strategy, trading_pair, exchange, initial_investment, current_value, is_virtual, settings, status)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'stopped')
            RETURNING *
        """, (bot_id, user["user_id"], bot_data.name, bot_data.strategy, bot_data.trading_pair, bot_data.exchange, bot_data.initial_investment, bot_data.initial_investment, bot_data.is_virtual, json.dumps(bot_data.settings)))
        
        bot = cur.fetchone()
        conn.commit()
        return dict(bot)
    finally:
        conn.close()

@app.get("/api/bots/{bot_id}")
async def get_bot(request: Request, bot_id: str):
    """Get a specific bot"""
    user = await get_current_user(request)
    
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT * FROM bots WHERE bot_id = %s AND user_id = %s
        """, (bot_id, user["user_id"]))
        bot = cur.fetchone()
        if not bot:
            raise HTTPException(status_code=404, detail="Bot not found")
        return dict(bot)
    finally:
        conn.close()

@app.put("/api/bots/{bot_id}")
async def update_bot(request: Request, bot_id: str, bot_data: BotUpdate):
    """Update a bot"""
    user = await get_current_user(request)
    
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        
        # Build update query dynamically
        updates = []
        values = []
        if bot_data.name:
            updates.append("name = %s")
            values.append(bot_data.name)
        if bot_data.status:
            updates.append("status = %s")
            values.append(bot_data.status)
        if bot_data.settings:
            updates.append("settings = %s")
            values.append(json.dumps(bot_data.settings))
        
        updates.append("updated_at = NOW()")
        values.extend([bot_id, user["user_id"]])
        
        cur.execute(f"""
            UPDATE bots SET {', '.join(updates)}
            WHERE bot_id = %s AND user_id = %s
            RETURNING *
        """, values)
        
        bot = cur.fetchone()
        conn.commit()
        
        if not bot:
            raise HTTPException(status_code=404, detail="Bot not found")
        return dict(bot)
    finally:
        conn.close()

@app.delete("/api/bots/{bot_id}")
async def delete_bot(request: Request, bot_id: str):
    """Delete a bot"""
    user = await get_current_user(request)
    
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("""
            DELETE FROM bots WHERE bot_id = %s AND user_id = %s RETURNING bot_id
        """, (bot_id, user["user_id"]))
        deleted = cur.fetchone()
        conn.commit()
        
        if not deleted:
            raise HTTPException(status_code=404, detail="Bot not found")
        return {"message": "Bot deleted successfully"}
    finally:
        conn.close()

@app.post("/api/bots/{bot_id}/start")
async def start_bot(request: Request, bot_id: str):
    """Start a bot"""
    user = await get_current_user(request)
    
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("""
            UPDATE bots SET status = 'running', updated_at = NOW()
            WHERE bot_id = %s AND user_id = %s
            RETURNING *
        """, (bot_id, user["user_id"]))
        bot = cur.fetchone()
        conn.commit()
        
        if not bot:
            raise HTTPException(status_code=404, detail="Bot not found")
        return dict(bot)
    finally:
        conn.close()

@app.post("/api/bots/{bot_id}/stop")
async def stop_bot(request: Request, bot_id: str):
    """Stop a bot"""
    user = await get_current_user(request)
    
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("""
            UPDATE bots SET status = 'stopped', updated_at = NOW()
            WHERE bot_id = %s AND user_id = %s
            RETURNING *
        """, (bot_id, user["user_id"]))
        bot = cur.fetchone()
        conn.commit()
        
        if not bot:
            raise HTTPException(status_code=404, detail="Bot not found")
        return dict(bot)
    finally:
        conn.close()

# Crypto Prices (Mock data for demo)
@app.get("/api/crypto/prices")
async def get_crypto_prices(limit: int = 10):
    """Get cryptocurrency prices"""
    mock_data = [
        {"id": "bitcoin", "symbol": "BTC", "name": "Bitcoin", "current_price": 98500.00, "price_change_24h": 1250.00, "percent_change_24h": 1.28, "market_cap": 1950000000000, "volume_24h": 45000000000},
        {"id": "ethereum", "symbol": "ETH", "name": "Ethereum", "current_price": 3450.00, "price_change_24h": 85.00, "percent_change_24h": 2.52, "market_cap": 415000000000, "volume_24h": 18000000000},
        {"id": "solana", "symbol": "SOL", "name": "Solana", "current_price": 195.00, "price_change_24h": 12.50, "percent_change_24h": 6.85, "market_cap": 92000000000, "volume_24h": 5500000000},
        {"id": "binancecoin", "symbol": "BNB", "name": "BNB", "current_price": 715.00, "price_change_24h": -8.50, "percent_change_24h": -1.17, "market_cap": 105000000000, "volume_24h": 2200000000},
        {"id": "xrp", "symbol": "XRP", "name": "XRP", "current_price": 2.35, "price_change_24h": 0.18, "percent_change_24h": 8.29, "market_cap": 135000000000, "volume_24h": 12000000000},
        {"id": "cardano", "symbol": "ADA", "name": "Cardano", "current_price": 1.05, "price_change_24h": 0.08, "percent_change_24h": 8.25, "market_cap": 37000000000, "volume_24h": 1800000000},
        {"id": "dogecoin", "symbol": "DOGE", "name": "Dogecoin", "current_price": 0.42, "price_change_24h": 0.03, "percent_change_24h": 7.69, "market_cap": 62000000000, "volume_24h": 4500000000},
        {"id": "avalanche", "symbol": "AVAX", "name": "Avalanche", "current_price": 48.50, "price_change_24h": 3.20, "percent_change_24h": 7.06, "market_cap": 20000000000, "volume_24h": 850000000},
        {"id": "polkadot", "symbol": "DOT", "name": "Polkadot", "current_price": 9.25, "price_change_24h": 0.45, "percent_change_24h": 5.11, "market_cap": 14000000000, "volume_24h": 550000000},
        {"id": "chainlink", "symbol": "LINK", "name": "Chainlink", "current_price": 24.80, "price_change_24h": 1.85, "percent_change_24h": 8.06, "market_cap": 15500000000, "volume_24h": 1200000000}
    ]
    return {"data": mock_data[:limit], "timestamp": datetime.now(timezone.utc).isoformat()}

@app.get("/api/crypto/market-stats")
async def get_market_stats():
    """Get global market statistics"""
    return {
        "total_market_cap": 3450000000000,
        "total_volume_24h": 125000000000,
        "btc_dominance": 56.5,
        "eth_dominance": 12.0,
        "active_cryptocurrencies": 10000,
        "markets": 850
    }

@app.get("/api/crypto/trading-pairs")
async def get_trading_pairs():
    """Get available trading pairs"""
    pairs = [
        {"symbol": "BTC/USDT", "base": "BTC", "quote": "USDT", "price": 98500.00, "change_24h": 1.28},
        {"symbol": "ETH/USDT", "base": "ETH", "quote": "USDT", "price": 3450.00, "change_24h": 2.52},
        {"symbol": "SOL/USDT", "base": "SOL", "quote": "USDT", "price": 195.00, "change_24h": 6.85},
        {"symbol": "BNB/USDT", "base": "BNB", "quote": "USDT", "price": 715.00, "change_24h": -1.17},
        {"symbol": "XRP/USDT", "base": "XRP", "quote": "USDT", "price": 2.35, "change_24h": 8.29},
        {"symbol": "ADA/USDT", "base": "ADA", "quote": "USDT", "price": 1.05, "change_24h": 8.25},
        {"symbol": "DOGE/USDT", "base": "DOGE", "quote": "USDT", "price": 0.42, "change_24h": 7.69},
        {"symbol": "AVAX/USDT", "base": "AVAX", "quote": "USDT", "price": 48.50, "change_24h": 7.06},
        {"symbol": "DOT/USDT", "base": "DOT", "quote": "USDT", "price": 9.25, "change_24h": 5.11},
        {"symbol": "LINK/USDT", "base": "LINK", "quote": "USDT", "price": 24.80, "change_24h": 8.06},
        {"symbol": "ETH/BTC", "base": "ETH", "quote": "BTC", "price": 0.035, "change_24h": 1.24},
        {"symbol": "SOL/BTC", "base": "SOL", "quote": "BTC", "price": 0.00198, "change_24h": 5.57}
    ]
    return pairs

# Health check
@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()}

@app.get("/api")
async def root():
    return {"message": "TensorX API", "version": "1.0.0"}

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
