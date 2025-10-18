from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
from typing import Annotated, List
from dotenv import load_dotenv
import os
import hashlib

from database import Base, engine, get_db
from models import User, PasswordEntry
from schemas import (
    UserCreate, UserResponse,
    Token, TokenData,
    PasswordEntryCreate, PasswordEntryResponse
)

# Load environment variables
load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI(title="User Authentication API", version="2.0")

# Create tables
Base.metadata.create_all(bind=engine)


# ✅ Secure Password Handling (SHA256 + Bcrypt)
def get_password_hash(password: str) -> str:
    if not isinstance(password, str):
        raise TypeError("Password must be a string")
    sha256_hashed = hashlib.sha256(password.encode("utf-8")).hexdigest()
    return pwd_context.hash(sha256_hashed)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    sha256_hashed = hashlib.sha256(plain_password.encode("utf-8")).hexdigest()
    return pwd_context.verify(sha256_hashed, hashed_password)


# ✅ Token Utilities
def create_access_token(data: dict, expires_delta=None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# ✅ Database Utils
def get_user_by_email(db: Session, email: str):
    return db.query(User).filter(User.email == email).first()


# ✅ Auth Dependency
async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    db: Session = Depends(get_db)
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = get_user_by_email(db, email=email)
    if user is None:
        raise credentials_exception
    return user


# ✅ Routes
@app.get("/")
def root():
    return {"message": "Welcome to the PostgreSQL-powered Auth API!"}


@app.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register_user(user_data: UserCreate, db: Session = Depends(get_db)):
    existing_user = get_user_by_email(db, user_data.email)
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_pw = get_password_hash(user_data.password)
    new_user = User(email=user_data.email, hashed_password=hashed_pw)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user


@app.post("/token", response_model=Token)
def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Session = Depends(get_db)
):
    user = get_user_by_email(db, form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(
        data={"sub": user.email},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me", response_model=UserResponse)
def read_users_me(current_user: Annotated[User, Depends(get_current_user)]):
    return current_user


@app.post("/passwords", response_model=PasswordEntryResponse)
def create_password_entry(
    password_data: PasswordEntryCreate,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db)
):
    entry = PasswordEntry(**password_data.dict(), owner_id=current_user.id)
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry


@app.get("/passwords", response_model=List[PasswordEntryResponse])
def get_all_passwords(current_user: Annotated[User, Depends(get_current_user)], db: Session = Depends(get_db)):
    return db.query(PasswordEntry).filter(PasswordEntry.owner_id == current_user.id).all()


@app.post("/logout")
def logout_user():
    return {"message": "Logout successful. Please delete your token client-side."}
