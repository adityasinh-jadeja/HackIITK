"""
WebSocket connection manager for real-time dashboard updates.
"""
import json
import asyncio
from fastapi import WebSocket

class WebSocketManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []
        self.current_state = {
            "overallRisk": 0,
            "metrics": {"blocked": 0, "allowed": 0, "overrides": 0, "latency": 0.0},
            "threats": [],
            "currentGoal": "Waiting for agent command...",
            "agentStatus": "idle",
        }
        self.hitl_events: dict[str, asyncio.Event] = {}
        self.hitl_results: dict[str, bool] = {}

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        await websocket.send_json({"type": "DASHBOARD_UPDATE", "data": self.current_state})

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, data: dict):
        payload = data.get("data", data)
        msg_type = data.get("type", "DASHBOARD_UPDATE")

        # Reset current state on new evaluation to prevent stale data
        if msg_type == "SECURITY_EVALUATION" or msg_type == "AGENT_CLEARED":
            self.current_state = {
                "overallRisk": 0,
                "metrics": self.current_state.get("metrics", {"blocked": 0, "allowed": 0, "overrides": 0, "latency": 0.0}),
                "threats": [],
                "currentGoal": "Waiting for agent command...",
                "agentStatus": "idle",
            }

        # LIVE_FRAME is high-frequency ephemeral data — skip state caching
        if msg_type != "LIVE_FRAME":
            self.current_state.update(payload)
        
        message = json.dumps({"type": msg_type, "data": payload})
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception:
                disconnected.append(connection)
        for conn in disconnected:
            self.disconnect(conn)

    async def handle_message(self, raw: str):
        data = json.loads(raw)
        msg_type = data.get("type")
        if msg_type == "HITL_RESPONSE":
            request_id = data.get("requestId")
            approved = data.get("approved", False)
            action = "ALLOW" if approved else "BLOCK"
            
            # Resolve pending HITL wait if tracked
            if request_id and request_id in self.hitl_events:
                self.hitl_results[request_id] = approved
                self.hitl_events[request_id].set()
                
            await self.broadcast({
                "type": "HITL_RESOLVED",
                "data": {
                    "requestId": request_id,
                    "approved": approved,
                    "action": action,
                }
            })

    def get_current_state(self):
        return self.current_state

ws_manager = WebSocketManager()
