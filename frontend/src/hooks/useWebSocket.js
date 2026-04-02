import { useState, useEffect, useRef, useCallback } from 'react';

const WS_URL = 'ws://localhost:8000/ws/dashboard';

export function useWebSocket() {
  const [connected, setConnected] = useState(false);
  const [dashboardData, setDashboardData] = useState(null);
  const [hitlRequest, setHitlRequest] = useState(null);
  const wsRef = useRef(null);
  const reconnectTimerRef = useRef(null);

  const handleMessage = useCallback((event) => {
    const msg = JSON.parse(event.data);

    if (msg.type === 'DASHBOARD_UPDATE') {
      setDashboardData(prev => ({ ...prev, ...msg.data }));

    } else if (msg.type === 'SCAN_COMPLETE' || msg.type === 'SCAN_STARTED') {
      setDashboardData(prev => ({ ...prev, ...msg.data }));

    } else if (msg.type === 'SECURITY_EVALUATION') {
      // Replace dashboard state entirely with new evaluation
      // (don't merge old stale data from previous scans)
      setDashboardData(prev => ({
        // Keep only session-level fields from previous state
        currentGoal: prev?.currentGoal || 'General browsing',
        metrics: prev?.metrics || { blocked: 0, allowed: 0, overrides: 0, latency: 0 },
        // Set everything else from the new evaluation
        url: msg.data.url,
        overallRisk: msg.data.overallRisk,
        action: msg.data.action,
        threats: msg.data.threats,
        llmVerdict: msg.data.llmVerdict,
        policyDecision: msg.data.policyDecision,
        latency: msg.data.latency,
        requestId: msg.data.requestId,
        agentStatus: msg.data.agentStatus,
        // Phase 4: Preserve sandbox/network data across evaluation
        sandboxed: msg.data.sandboxed || false,
        sessionId: msg.data.sessionId || null,
        // Keep network data from previous NETWORK_ACTIVITY events
        networkLog: prev?.networkLog || [],
        networkStats: prev?.networkStats || {},
        sandboxStatus: prev?.sandboxStatus || {},
      }));

      // Trigger HITL modal if REQUIRE_APPROVAL
      if (msg.data.action === 'REQUIRE_APPROVAL') {
        setHitlRequest(msg.data);
      }

    } else if (msg.type === 'NETWORK_ACTIVITY') {
      // Phase 4: Network activity from sandboxed browser
      setDashboardData(prev => ({
        ...prev,
        networkLog: msg.data.network_log || [],
        networkStats: msg.data.network_stats || {},
      }));

    } else if (msg.type === 'SANDBOX_STATUS') {
      // Phase 4: Sandbox session status update
      setDashboardData(prev => ({
        ...prev,
        sandboxStatus: {
          sessionId: msg.data.session_id,
          active: msg.data.active,
          sessions: msg.data.sessions || [],
          permissions: msg.data.permissions || {},
        },
      }));

    } else if (msg.type === 'HITL_RESOLVED') {
      setHitlRequest(null);
      setDashboardData(prev => ({
        ...prev,
        action: msg.data.action,
        hitlResolved: msg.data,
      }));

    } else if (msg.type === 'LIVE_FRAME') {
      // CDP Screencast: continuous live video frames
      setDashboardData(prev => ({
        ...prev,
        liveFrame: msg.data.frame,  // base64 JPEG from CDP
      }));

    } else if (msg.type === 'AGENT_STEP') {
      // Phase 5: Agent reasoning step (no screenshot — that's handled by LIVE_FRAME)
      setDashboardData(prev => ({
        ...prev,
        agentStatus: msg.data.agentStatus,
        currentGoal: msg.data.currentGoal,
        currentUrl: msg.data.currentUrl,
        agentStepInfo: msg.data.stepInfo,
        agentStepsLog: msg.data.stepsLog || [],
      }));

    } else if (msg.type === 'AGENT_STARTED') {
      setDashboardData(prev => ({
        ...prev,
        agentStatus: 'started',
        currentGoal: msg.data?.goal || prev?.currentGoal,
        agentStepsLog: [],
        liveFrame: null,
      }));

    } else if (msg.type === 'AGENT_STOPPED') {
      setDashboardData(prev => ({
        ...prev,
        agentStatus: 'idle',
      }));

    } else if (msg.type === 'AGENT_CLEARED') {
      setDashboardData(null);
    }
  }, []);

  const connectWebSocket = useCallback(() => {
    // Clean up previous connection
    if (wsRef.current) {
      wsRef.current.onopen = null;
      wsRef.current.onclose = null;
      wsRef.current.onmessage = null;
      try { wsRef.current.close(); } catch (_) {}
    }

    const ws = new WebSocket(WS_URL);
    wsRef.current = ws;

    ws.onopen = () => setConnected(true);

    ws.onclose = () => {
      setConnected(false);
      // Auto-reconnect after 3 seconds — properly re-wire handlers
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
      reconnectTimerRef.current = setTimeout(() => {
        connectWebSocket();
      }, 3000);
    };

    ws.onmessage = handleMessage;
  }, [handleMessage]);

  useEffect(() => {
    connectWebSocket();
    return () => {
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
      if (wsRef.current) {
        wsRef.current.onclose = null; // Prevent reconnect on unmount
        wsRef.current.close();
      }
    };
  }, [connectWebSocket]);

  const sendMessage = useCallback((type, payload) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ type, ...payload }));
    }
  }, []);

  const clearState = useCallback(() => {
    setDashboardData(null);
    setHitlRequest(null);
  }, []);

  const respondToHitl = useCallback(async (requestId, approved) => {
    try {
      await fetch('http://localhost:8000/api/hitl/respond', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ requestId, approved }),
      });
    } catch (err) {
      console.error('HITL respond failed:', err);
    }
    setHitlRequest(null);
  }, []);

  return { connected, dashboardData, sendMessage, hitlRequest, respondToHitl, clearState };
}
