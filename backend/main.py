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
    
    
@app.post('/logout')
async def logout_user():
    return {"message": "Logout successful"}

@app.get('/user/{user_id}')
async def get_user(user_id : int):
    return {"user_id": user_id, 'message': "your passwords and emails are safe with us"}