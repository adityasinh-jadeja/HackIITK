"""
WebSocket connection manager for real-time dashboard updates.
"""
import json
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
        if msg_type == "SECURITY_EVALUATION":
            self.current_state = {
                "overallRisk": 0,
                "metrics": self.current_state.get("metrics", {"blocked": 0, "allowed": 0, "overrides": 0, "latency": 0.0}),
                "threats": [],
                "currentGoal": self.current_state.get("currentGoal", "Waiting for agent command..."),
                "agentStatus": "idle",
            }

        self.current_state.update(payload)
        
        message = json.dumps({"type": msg_type, "data": payload})
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception:
                self.disconnect(connection)

    async def handle_message(self, raw: str):
        data = json.loads(raw)
        msg_type = data.get("type")
        if msg_type == "HITL_RESPONSE":
            request_id = data.get("requestId")
            approved = data.get("approved", False)
            action = "ALLOW" if approved else "BLOCK"
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
