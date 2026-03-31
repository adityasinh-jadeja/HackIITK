"""
CRUD operations for MongoDB collections.
Collections: sessions, threats, policy_decisions, network_logs
"""
from datetime import datetime, timezone, timedelta
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

async def get_cached_llm_verdict(url: str, goal: str, dom_risk_score: float):
    """Retrieve a recent LLM verdict from the database to save API calls/GPU cycles."""
    db = get_db()
    # Consider cache valid for 1 hour
    threshold = datetime.now(timezone.utc) - timedelta(hours=1)
    
    # We use dom_risk_score as a proxy for DOM structure changes.
    # If the risk score is the same, the DOM threats are likely the same.
    record = await db.llm_cache.find_one({
        "url": url,
        "goal": goal,
        "dom_risk_score": dom_risk_score,
        "cached_at": {"$gt": threshold}
    })
    return record

async def cache_llm_verdict(url: str, goal: str, dom_risk_score: float, verdict_data: dict):
    """Save an LLM verdict to the database."""
    db = get_db()
    document = {
        "url": url,
        "goal": goal,
        "dom_risk_score": dom_risk_score,
        "verdict": verdict_data,
        "cached_at": datetime.now(timezone.utc)
    }
    await db.llm_cache.insert_one(document)

