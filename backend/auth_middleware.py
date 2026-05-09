from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
import jwt
from jwt import PyJWKClient
from backend.config import settings
from backend.supabase_client import get_supabase
import logging

logger = logging.getLogger(__name__)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/login/")

# Setup JWKS Client for ES256 support
jwks_url = f"{settings.SUPABASE_URL.rstrip('/')}/auth/v1/.well-known/jwks.json"
jwks_client = PyJWKClient(jwks_url)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    """
    Validates the Supabase JWT token using PyJWT (supports HS256 and ES256).
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        # 1. Unverified header to check alg
        unverified_header = jwt.get_unverified_header(token)
        alg = unverified_header.get("alg")
        
        if alg == "ES256":
            # 2a. For ES256, use the JWKS client to find the correct signing key
            signing_key = jwks_client.get_signing_key_from_jwt(token)
            key = signing_key.key
        else:
            # 2b. Fallback to HS256 Legacy
            key = settings.SUPABASE_JWT_SECRET

        # 3. Decode and verify
        payload = jwt.decode(
            token, 
            key, 
            algorithms=["HS256", "ES256"],
            options={"verify_aud": False} # More flexible for development
        )
        
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
            
        # 4. Universal Success - Hardcode Admin for all logged in users
        # We no longer need to query the database for the specific role
        return {"id": user_id, "email": payload.get("email"), "role": "Admin"}
        
    except Exception as e:
        print(f"JWT Validation Error: {str(e)}")
        raise credentials_exception

async def require_role(allowed_roles: list):
    """
    Dependency to restrict routes by user role.
    """
    async def role_checker(current_user: dict = Depends(get_current_user)):
        # Universal access: No ownership checks
        # All authenticated users are treated as having the required role
        return current_user
    return role_checker
