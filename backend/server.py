from fastapi import FastAPI, APIRouter, HTTPException, Depends, UploadFile, File
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, timezone, timedelta
import bcrypt
import jwt
import secrets
import string
import base64

# ===== Load ENV =====
ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# ===== MongoDB =====
mongo_url = os.environ["MONGO_URL"]
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ["DB_NAME"]]

# ===== JWT =====
JWT_SECRET = os.environ.get("JWT_SECRET", secrets.token_urlsafe(32))
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

# ===== Security =====
security = HTTPBearer()

# ===== FastAPI Setup =====
app = FastAPI()
api_router = APIRouter(prefix="/api")

# ===== Models =====
class User(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    username: str
    password_hash: str
    role: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class UserRegister(BaseModel):
    username: str
    password: str
    access_code: str

class UserLogin(BaseModel):
    username: str
    password: str

class AccessCode(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    code: str
    role: str
    used: bool = False

class Card(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    section: str
    title: str
    content: str
    order: int = 0
    created_by: str
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class CardCreate(BaseModel):
    section: str
    title: str
    content: str
    order: int = 0

class CardUpdate(BaseModel):
    title: Optional[str] = None
    content: Optional[str] = None
    order: Optional[int] = None

class Submission(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    username: str
    section: str
    data: Dict[str, Any]
    status: str = "pending"
    viewed: bool = False
    admin_notes: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class SubmissionCreate(BaseModel):
    section: str
    data: Dict[str, Any]

class SubmissionUpdate(BaseModel):
    status: str
    admin_notes: Optional[str] = None

# ===== Utility =====
def generate_access_code(length=8):
    return ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(length))

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_token(user_id: str, username: str, role: str) -> str:
    payload = {
        "user_id": user_id,
        "username": username,
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    payload = decode_token(token)
    user = await db.users.find_one({"id": payload["user_id"]}, {"_id": 0})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

async def require_admin(user: dict = Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user

# ===== Startup =====
@app.on_event("startup")
async def startup_event():
    existing_codes = await db.access_codes.count_documents({})
    if existing_codes == 0:
        admin_code = AccessCode(code=generate_access_code(), role="admin")
        member_code = AccessCode(code=generate_access_code(), role="member")
        await db.access_codes.insert_many([admin_code.model_dump(), member_code.model_dump()])
        logger.info(f"Admin Code: {admin_code.code}")
        logger.info(f"Member Code: {member_code.code}")

# ===== Auth =====
@api_router.post("/auth/register")
async def register(user_data: UserRegister):
    existing_user = await db.users.find_one({"username": user_data.username})
    if existing_user:
        raise HTTPException(status_code=400, detail="Username exists")

    access_code = await db.access_codes.find_one({"code": user_data.access_code, "used": False})
    if not access_code:
        raise HTTPException(status_code=400, detail="Invalid code")

    user = User(
        username=user_data.username,
        password_hash=hash_password(user_data.password),
        role=access_code["role"]
    )
    await db.users.insert_one(user.model_dump())
    await db.access_codes.update_one({"code": user_data.access_code}, {"$set": {"used": True}})

    token = create_token(user.id, user.username, user.role)
    return {"token": token, "user": user.model_dump()}

@api_router.post("/auth/login")
async def login(user_data: UserLogin):
    user = await db.users.find_one({"username": user_data.username}, {"_id": 0})
    if not user or not verify_password(user_data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_token(user["id"], user["username"], user["role"])
    return {"token": token, "user": user}

@api_router.get("/auth/me")
async def get_me(user: dict = Depends(get_current_user)):
    return user

# ===== Cards =====
@api_router.get("/cards")
async def get_cards(section: Optional[str] = None):
    query = {"section": section} if section else {}
    return await db.cards.find(query, {"_id": 0}).sort("order", 1).to_list(1000)

@api_router.post("/cards")
async def create_card(card_data: CardCreate, user: dict = Depends(require_admin)):
    card = Card(**card_data.model_dump(), created_by=user["username"])
    await db.cards.insert_one(card.model_dump())
    return card

# ===== Health =====
@api_router.get("/")
async def root():
    return {"message": "UKBRUM Media API Active"}

app.include_router(api_router)

# ===== CORS =====
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ===== Logging =====
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "server:app",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 10000)),
        reload=False
    )
