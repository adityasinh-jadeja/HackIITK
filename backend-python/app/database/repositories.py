"""
CRUD operations for MongoDB collections.
Collections: sessions, threats, policy_decisions, network_logs
"""
from datetime import datetime, timezone
from app.database.connection import get_db

async def create_session(session_data: dict) -> str:
    db = get_db()
    session_data["created_at"] = datetime.now(timezone.utc)
    result = await db.sessions.insert_one(session_data)
    return str(result.inserted_id)

async def log_threat(threat_data: dict):
    db = get_db()
    threat_data["detected_at"] = datetime.now(timezone.utc)
    await db.threats.insert_one(threat_data)

async def log_policy_decision(decision_data: dict):
    db = get_db()
    decision_data["decided_at"] = datetime.now(timezone.utc)
    await db.policy_decisions.insert_one(decision_data)

async def get_sessions(limit: int = 50):
    db = get_db()
    cursor = db.sessions.find().sort("created_at", -1).limit(limit)
    return await cursor.to_list(length=limit)

async def get_threats(session_id: str = None, limit: int = 100):
    db = get_db()
    query = {"session_id": session_id} if session_id else {}
    cursor = db.threats.find(query).sort("detected_at", -1).limit(limit)
    return await cursor.to_list(length=limit)
