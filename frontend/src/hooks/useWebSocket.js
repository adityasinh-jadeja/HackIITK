import { useState, useEffect, useRef, useCallback } from 'react';

const WS_URL = 'ws://localhost:8000/ws/dashboard';

export function useWebSocket() {
  const [connected, setConnected] = useState(false);
  const [dashboardData, setDashboardData] = useState(null);
  const wsRef = useRef(null);

  useEffect(() => {
    const ws = new WebSocket(WS_URL);
    wsRef.current = ws;

    ws.onopen = () => setConnected(true);
    ws.onclose = () => {
      setConnected(false);
      // Auto-reconnect after 3 seconds
      setTimeout(() => {
        wsRef.current = new WebSocket(WS_URL);
      }, 3000);
    };
    ws.onmessage = (event) => {
      const msg = JSON.parse(event.data);
      if (msg.type === 'DASHBOARD_UPDATE') {
        setDashboardData(msg.data);
      }
    };

    return () => ws.close();
  }, []);

  const sendMessage = useCallback((type, payload) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ type, ...payload }));
    }
  }, []);

  return { connected, dashboardData, sendMessage };
}
