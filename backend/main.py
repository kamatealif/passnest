from fastapi import FastAPI
from pydantic import BaseModel, EmailStr, Field
from typing import Annotated


app = FastAPI()

class User(BaseModel):
    email: Annotated[EmailStr, Field(..., description="Email of the user")]
    password: Annotated[str, Field(..., description="Password of the user")]
    

@app.get("/")
async def root():
    return {"message": "Hello World"}

@app.post('/login')
async def login_user(user_credentials : User):
    return {"message": "Login successful"}

@app.post('/register')
async def register_user(user_credentials : User):
    