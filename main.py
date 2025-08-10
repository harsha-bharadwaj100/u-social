from http import client
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, EmailStr
from motor.motor_asyncio import AsyncIOMotorClient
from passlib.context import CryptContext

app = FastAPI()

# MongoDB setup
client = AsyncIOMotorClient("mongodb://localhost:27017")
db = client.social_app
users_collection = db.users

# Password hashing setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class UserRegister(BaseModel):
    username: str
    email: EmailStr
    password: str


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


@app.post("/register")
async def register_user(user: UserRegister):
    # Check if user already exists
    existing_user = await users_collection.find_one({"email": user.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")

    # Hash the password
    hashed_password = hash_password(user.password)

    # Insert user into collection
    user_data = {
        "username": user.username,
        "email": user.email,
        "password": hashed_password,
    }

    await users_collection.insert_one(user_data)
    return {"message": "User registered successfully"}
