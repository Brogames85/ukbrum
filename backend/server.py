from fastapi import FastAPI, APIRouter, HTTPException, Depends, UploadFile, File, Form
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

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['from fastapi import FastAPI, APIRouter, HTTPException, Depends, UploadFile, File, Form
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

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ["MONGO_URL"]
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# JWT Configuration
JWT_SECRET = os.environ.get('JWT_SECRET', secrets.token_urlsafe(32))
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

# Security
security = HTTPBearer()

# Create the main app
app = FastAPI()
api_router = APIRouter(prefix="/api")

# ==================== MODELS ====================

class User(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    username: str
    password_hash: str
    role: str  # "admin" or "member"
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
    section: str  # "community", "photography", "videography", "streaming"
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
    data: Dict[str, Any]  # Varies by section
    status: str = "pending"  # "pending", "accepted", "denied"
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

# ==================== UTILITY FUNCTIONS ====================

def generate_access_code(length=8):
    """Generate a random access code"""
    return ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(length))

def hash_password(password: str) -> str:
    """Hash a password"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    """Verify a password"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_token(user_id: str, username: str, role: str) -> str:
    """Create JWT token"""
    payload = {
        "user_id": user_id,
        "username": username,
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def decode_token(token: str) -> dict:
    """Decode JWT token"""
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get current user from token"""
    token = credentials.credentials
    payload = decode_token(token)
    user = await db.users.find_one({"id": payload["user_id"]}, {"_id": 0})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

async def require_admin(user: dict = Depends(get_current_user)):
    """Require admin role"""
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user

# ==================== INITIALIZATION ====================

@app.on_event("startup")
async def startup_event():
    """Initialize access codes on startup"""
    # Check if codes already exist
    existing_codes = await db.access_codes.count_documents({})
    if existing_codes == 0:
        admin_code = generate_access_code()
        member_code = generate_access_code()
        
        admin_code_obj = AccessCode(code=admin_code, role="admin")
        member_code_obj = AccessCode(code=member_code, role="member")
        
        await db.access_codes.insert_one(admin_code_obj.model_dump())
        await db.access_codes.insert_one(member_code_obj.model_dump())
        
        logger.info(f"Generated Admin Code: {admin_code}")
        logger.info(f"Generated Member Code: {member_code}")

# ==================== AUTH ROUTES ====================

@api_router.post("/auth/register")
async def register(user_data: UserRegister):
    """Register a new user with access code"""
    # Check if username already exists
    existing_user = await db.users.find_one({"username": user_data.username})
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    # Verify access code
    access_code = await db.access_codes.find_one({"code": user_data.access_code, "used": False})
    if not access_code:
        raise HTTPException(status_code=400, detail="Invalid or already used access code")
    
    # Create user
    user = User(
        username=user_data.username,
        password_hash=hash_password(user_data.password),
        role=access_code["role"]
    )
    
    await db.users.insert_one(user.model_dump())
    
    # Mark code as used
    await db.access_codes.update_one(
        {"code": user_data.access_code},
        {"$set": {"used": True}}
    )
    
    # Create token
    token = create_token(user.id, user.username, user.role)
    
    return {
        "token": token,
        "user": {
            "id": user.id,
            "username": user.username,
            "role": user.role
        }
    }

@api_router.post("/auth/login")
async def login(user_data: UserLogin):
    """Login user"""
    user = await db.users.find_one({"username": user_data.username}, {"_id": 0})
    if not user or not verify_password(user_data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_token(user["id"], user["username"], user["role"])
    
    return {
        "token": token,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"]
        }
    }

@api_router.get("/auth/me")
async def get_me(user: dict = Depends(get_current_user)):
    """Get current user info"""
    return {
        "id": user["id"],
        "username": user["username"],
        "role": user["role"]
    }

@api_router.get("/codes")
async def get_codes(user: dict = Depends(require_admin)):
    """Get access codes (admin only)"""
    codes = await db.access_codes.find({}, {"_id": 0}).to_list(100)
    return codes

# ==================== CARD ROUTES ====================

@api_router.get("/cards")
async def get_cards(section: Optional[str] = None):
    """Get all cards or cards by section"""
    query = {"section": section} if section else {}
    cards = await db.cards.find(query, {"_id": 0}).sort("order", 1).to_list(1000)
    return cards

@api_router.post("/cards")
async def create_card(card_data: CardCreate, user: dict = Depends(require_admin)):
    """Create a new card (admin only)"""
    card = Card(
        **card_data.model_dump(),
        created_by=user["username"]
    )
    await db.cards.insert_one(card.model_dump())
    return card

@api_router.put("/cards/{card_id}")
async def update_card(card_id: str, card_data: CardUpdate, user: dict = Depends(require_admin)):
    """Update a card (admin only)"""
    update_data = {k: v for k, v in card_data.model_dump().items() if v is not None}
    update_data["updated_at"] = datetime.now(timezone.utc)
    
    result = await db.cards.update_one(
        {"id": card_id},
        {"$set": update_data}
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Card not found")
    
    updated_card = await db.cards.find_one({"id": card_id}, {"_id": 0})
    return updated_card

@api_router.delete("/cards/{card_id}")
async def delete_card(card_id: str, user: dict = Depends(require_admin)):
    """Delete a card (admin only)"""
    result = await db.cards.delete_one({"id": card_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Card not found")
    return {"message": "Card deleted successfully"}

# ==================== SUBMISSION ROUTES ====================

@api_router.post("/submissions")
async def create_submission(submission_data: SubmissionCreate, user: dict = Depends(get_current_user)):
    """Create a new submission"""
    submission = Submission(
        user_id=user["id"],
        username=user["username"],
        **submission_data.model_dump()
    )
    await db.submissions.insert_one(submission.model_dump())
    return submission

@api_router.get("/submissions")
async def get_submissions(user: dict = Depends(get_current_user)):
    """Get submissions (all for admin, own for members)"""
    if user["role"] == "admin":
        submissions = await db.submissions.find({}, {"_id": 0}).sort("created_at", -1).to_list(1000)
    else:
        submissions = await db.submissions.find({"user_id": user["id"]}, {"_id": 0}).sort("created_at", -1).to_list(1000)
    return submissions

@api_router.put("/submissions/{submission_id}")
async def update_submission(submission_id: str, update_data: SubmissionUpdate, user: dict = Depends(require_admin)):
    """Update submission status (admin only)"""
    result = await db.submissions.update_one(
        {"id": submission_id},
        {"$set": {
            "status": update_data.status,
            "admin_notes": update_data.admin_notes,
            "viewed": False,  # Reset viewed status when status changes
            "updated_at": datetime.now(timezone.utc)
        }}
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Submission not found")
    
    updated_submission = await db.submissions.find_one({"id": submission_id}, {"_id": 0})
    return updated_submission

@api_router.get("/submissions/notifications")
async def get_notifications(user: dict = Depends(get_current_user)):
    """Get unviewed notifications for user"""
    notifications = await db.submissions.find(
        {
            "user_id": user["id"],
            "viewed": False,
            "status": {"$in": ["accepted", "denied"]}
        },
        {"_id": 0}
    ).to_list(100)
    return notifications

@api_router.put("/submissions/{submission_id}/viewed")
async def mark_viewed(submission_id: str, user: dict = Depends(get_current_user)):
    """Mark submission as viewed"""
    result = await db.submissions.update_one(
        {"id": submission_id, "user_id": user["id"]},
        {"$set": {"viewed": True}}
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Submission not found")
    
    return {"message": "Marked as viewed"}

@api_router.post("/submissions/upload")
async def upload_file(file: UploadFile = File(...), user: dict = Depends(get_current_user)):
    """Upload a file and return base64 encoded data"""
    # Read file content
    content = await file.read()
    
    # Convert to base64
    base64_data = base64.b64encode(content).decode('utf-8')
    
    return {
        "filename": file.filename,
        "content_type": file.content_type,
        "data": f"data:{file.content_type};base64,{base64_data}"
    }

# ==================== HEALTH CHECK ====================

@api_router.get("/")
async def root():
    return {"message": "UKBRUM Media Division API"}

# Include router
app.include_router(api_router)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['move_car']]

# JWT Configuration
JWT_SECRET = os.environ.get('JWT_SECRET', secrets.token_urlsafe(32))
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

# Security
security = HTTPBearer()

# Create the main app
app = FastAPI()
api_router = APIRouter(prefix="/api")

# ==================== MODELS ====================

class User(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    username: str
    password_hash: str
    role: str  # "admin" or "member"
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
    section: str  # "community", "photography", "videography", "streaming"
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
    data: Dict[str, Any]  # Varies by section
    status: str = "pending"  # "pending", "accepted", "denied"
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

# ==================== UTILITY FUNCTIONS ====================

def generate_access_code(length=8):
    """Generate a random access code"""
    return ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(length))

def hash_password(password: str) -> str:
    """Hash a password"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    """Verify a password"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_token(user_id: str, username: str, role: str) -> str:
    """Create JWT token"""
    payload = {
        "user_id": user_id,
        "username": username,
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def decode_token(token: str) -> dict:
    """Decode JWT token"""
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get current user from token"""
    token = credentials.credentials
    payload = decode_token(token)
    user = await db.users.find_one({"id": payload["user_id"]}, {"_id": 0})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

async def require_admin(user: dict = Depends(get_current_user)):
    """Require admin role"""
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user

# ==================== INITIALIZATION ====================

@app.on_event("startup")
async def startup_event():
    """Initialize access codes on startup"""
    # Check if codes already exist
    existing_codes = await db.access_codes.count_documents({})
    if existing_codes == 0:
        admin_code = generate_access_code()
        member_code = generate_access_code()
        
        admin_code_obj = AccessCode(code=admin_code, role="admin")
        member_code_obj = AccessCode(code=member_code, role="member")
        
        await db.access_codes.insert_one(admin_code_obj.model_dump())
        await db.access_codes.insert_one(member_code_obj.model_dump())
        
        logger.info(f"Generated Admin Code: {admin_code}")
        logger.info(f"Generated Member Code: {member_code}")

# ==================== AUTH ROUTES ====================

@api_router.post("/auth/register")
async def register(user_data: UserRegister):
    """Register a new user with access code"""
    # Check if username already exists
    existing_user = await db.users.find_one({"username": user_data.username})
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    # Verify access code
    access_code = await db.access_codes.find_one({"code": user_data.access_code, "used": False})
    if not access_code:
        raise HTTPException(status_code=400, detail="Invalid or already used access code")
    
    # Create user
    user = User(
        username=user_data.username,
        password_hash=hash_password(user_data.password),
        role=access_code["role"]
    )
    
    await db.users.insert_one(user.model_dump())
    
    # Mark code as used
    await db.access_codes.update_one(
        {"code": user_data.access_code},
        {"$set": {"used": True}}
    )
    
    # Create token
    token = create_token(user.id, user.username, user.role)
    
    return {
        "token": token,
        "user": {
            "id": user.id,
            "username": user.username,
            "role": user.role
        }
    }

@api_router.post("/auth/login")
async def login(user_data: UserLogin):
    """Login user"""
    user = await db.users.find_one({"username": user_data.username}, {"_id": 0})
    if not user or not verify_password(user_data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_token(user["id"], user["username"], user["role"])
    
    return {
        "token": token,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"]
        }
    }

@api_router.get("/auth/me")
async def get_me(user: dict = Depends(get_current_user)):
    """Get current user info"""
    return {
        "id": user["id"],
        "username": user["username"],
        "role": user["role"]
    }

@api_router.get("/codes")
async def get_codes(user: dict = Depends(require_admin)):
    """Get access codes (admin only)"""
    codes = await db.access_codes.find({}, {"_id": 0}).to_list(100)
    return codes

# ==================== CARD ROUTES ====================

@api_router.get("/cards")
async def get_cards(section: Optional[str] = None):
    """Get all cards or cards by section"""
    query = {"section": section} if section else {}
    cards = await db.cards.find(query, {"_id": 0}).sort("order", 1).to_list(1000)
    return cards

@api_router.post("/cards")
async def create_card(card_data: CardCreate, user: dict = Depends(require_admin)):
    """Create a new card (admin only)"""
    card = Card(
        **card_data.model_dump(),
        created_by=user["username"]
    )
    await db.cards.insert_one(card.model_dump())
    return card

@api_router.put("/cards/{card_id}")
async def update_card(card_id: str, card_data: CardUpdate, user: dict = Depends(require_admin)):
    """Update a card (admin only)"""
    update_data = {k: v for k, v in card_data.model_dump().items() if v is not None}
    update_data["updated_at"] = datetime.now(timezone.utc)
    
    result = await db.cards.update_one(
        {"id": card_id},
        {"$set": update_data}
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Card not found")
    
    updated_card = await db.cards.find_one({"id": card_id}, {"_id": 0})
    return updated_card

@api_router.delete("/cards/{card_id}")
async def delete_card(card_id: str, user: dict = Depends(require_admin)):
    """Delete a card (admin only)"""
    result = await db.cards.delete_one({"id": card_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Card not found")
    return {"message": "Card deleted successfully"}

# ==================== SUBMISSION ROUTES ====================

@api_router.post("/submissions")
async def create_submission(submission_data: SubmissionCreate, user: dict = Depends(get_current_user)):
    """Create a new submission"""
    submission = Submission(
        user_id=user["id"],
        username=user["username"],
        **submission_data.model_dump()
    )
    await db.submissions.insert_one(submission.model_dump())
    return submission

@api_router.get("/submissions")
async def get_submissions(user: dict = Depends(get_current_user)):
    """Get submissions (all for admin, own for members)"""
    if user["role"] == "admin":
        submissions = await db.submissions.find({}, {"_id": 0}).sort("created_at", -1).to_list(1000)
    else:
        submissions = await db.submissions.find({"user_id": user["id"]}, {"_id": 0}).sort("created_at", -1).to_list(1000)
    return submissions

@api_router.put("/submissions/{submission_id}")
async def update_submission(submission_id: str, update_data: SubmissionUpdate, user: dict = Depends(require_admin)):
    """Update submission status (admin only)"""
    result = await db.submissions.update_one(
        {"id": submission_id},
        {"$set": {
            "status": update_data.status,
            "admin_notes": update_data.admin_notes,
            "viewed": False,  # Reset viewed status when status changes
            "updated_at": datetime.now(timezone.utc)
        }}
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Submission not found")
    
    updated_submission = await db.submissions.find_one({"id": submission_id}, {"_id": 0})
    return updated_submission

@api_router.get("/submissions/notifications")
async def get_notifications(user: dict = Depends(get_current_user)):
    """Get unviewed notifications for user"""
    notifications = await db.submissions.find(
        {
            "user_id": user["id"],
            "viewed": False,
            "status": {"$in": ["accepted", "denied"]}
        },
        {"_id": 0}
    ).to_list(100)
    return notifications

@api_router.put("/submissions/{submission_id}/viewed")
async def mark_viewed(submission_id: str, user: dict = Depends(get_current_user)):
    """Mark submission as viewed"""
    result = await db.submissions.update_one(
        {"id": submission_id, "user_id": user["id"]},
        {"$set": {"viewed": True}}
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Submission not found")
    
    return {"message": "Marked as viewed"}

@api_router.post("/submissions/upload")
async def upload_file(file: UploadFile = File(...), user: dict = Depends(get_current_user)):
    """Upload a file and return base64 encoded data"""
    # Read file content
    content = await file.read()
    
    # Convert to base64
    base64_data = base64.b64encode(content).decode('utf-8')
    
    return {
        "filename": file.filename,
        "content_type": file.content_type,
        "data": f"data:{file.content_type};base64,{base64_data}"
    }

# ==================== HEALTH CHECK ====================

@api_router.get("/")
async def root():
    return {"message": "UKBRUM Media Division API"}

# Include router
app.include_router(api_router)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
