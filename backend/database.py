from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv
import os

# Load .env variables
load_dotenv()

# ✅ Use Neon PostgreSQL URL from .env
SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL")

# ✅ Create the SQLAlchemy engine
engine = create_engine(SQLALCHEMY_DATABASE_URL)

# ✅ Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# ✅ Base class for models
Base = declarative_base()

# ✅ Dependency for DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
