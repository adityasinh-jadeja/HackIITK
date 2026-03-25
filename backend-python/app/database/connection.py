"""
Async MongoDB connection using Motor.
"""
from motor.motor_asyncio import AsyncIOMotorClient
from app.config import settings

client: AsyncIOMotorClient = None
db = None

async def connect_db():
    global client, db
    client = AsyncIOMotorClient(settings.MONGODB_URI)
    db = client.get_database("secure_browser")
    print("✅ MongoDB connected")

async def close_db():
    global client
    if client:
        client.close()
        print("🔌 MongoDB disconnected")

def get_db():
    return db
