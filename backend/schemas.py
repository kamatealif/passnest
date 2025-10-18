from pydantic import BaseModel, EmailStr

class UserCreate(BaseModel):
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    id: int
    email: EmailStr

    class Config:
        from_attributes = True  # replaces orm_mode in Pydantic v2


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    email: EmailStr | None = None


class PasswordEntryCreate(BaseModel):
    website: str
    username: str
    password: str


class PasswordEntryResponse(BaseModel):
    id: int
    website: str
    username: str
    password: str

    class Config:
        from_attributes = True
