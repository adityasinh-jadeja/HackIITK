import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, LayoutDashboard, Send, Square, Loader, Brain, Globe, MousePointer, Type, ArrowDown, Clock, CheckCircle, XCircle, AlertTriangle, Trash2 } from 'lucide-react';
import { useWebSocket } from '../hooks/useWebSocket';
import HITLApproval from './HITLApproval';
import './BrowserUI.css';

const ACTION_ICONS = {

  navigate: Globe,
  click: MousePointer,
  type: Type,
  scroll: ArrowDown,
  wait: Clock,
  finish: CheckCircle,
  think: Brain,
  error: XCircle,
  blocked: AlertTriangle,
  timeout: Clock,
};

const STATUS_COLORS = {
  planning: '#f59e0b',
  navigating: '#3b82f6',
  executing: '#8b5cf6',
  finished: '#22c55e',
  failed: '#ef4444',
  error: '#ef4444',
  awaiting_approval: '#f97316',
  started: '#06b6d4',
  idle: '#6b7280',
};

const BrowserUI = () => {
  const navigate = useNavigate();
  const [url, setUrl] = useState('');
  const [agentGoal, setAgentGoal] = useState('');
  const [isAgentRunning, setIsAgentRunning] = useState(false);

  const { connected: isBackendConnected, dashboardData, hitlRequest, respondToHitl } = useWebSocket();
  const globalRisk = dashboardData?.overallRisk || 0;
  const agentStatus = dashboardData?.agentStatus || 'idle';
  const liveFrame = dashboardData?.liveFrame;   // CDP screencast live frame
  const stepInfo = dashboardData?.agentStepInfo;
  const stepsLog = dashboardData?.agentStepsLog || [];
  const currentUrl = dashboardData?.currentUrl;

  let riskLevel = 'Safe';
  if (globalRisk > 70) riskLevel = 'Danger';
  else if (globalRisk > 40) riskLevel = 'Warning';

  useEffect(() => {
    if (agentStatus === 'finished' || agentStatus === 'failed' || agentStatus === 'error' || agentStatus === 'idle') {
      setIsAgentRunning(false);
    } else if (agentStatus === 'planning' || agentStatus === 'executing' || agentStatus === 'navigating' || agentStatus === 'started') {
      setIsAgentRunning(true);
    }
  }, [agentStatus]);

  // Auto-clear logic when returning to this page from dashboard
  // If the agent is NOT running, clear old state immediately.
  useEffect(() => {
    const shouldClear = agentStatus === 'finished' || agentStatus === 'failed' || agentStatus === 'error' || (agentStatus === 'idle' && (liveFrame || currentUrl));
    if (shouldClear) {
      handleClearSession();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []); // Run ONCE on mount

  // Update URL bar from agent navigation
  useEffect(() => {
    if (currentUrl && currentUrl !== 'about:blank') {
      setUrl(currentUrl);
    } else if (!currentUrl && !isAgentRunning) {
      // If cleared, reset URL
      setUrl('');
      setAgentGoal('');
    }
  }, [currentUrl, isAgentRunning]);

  const handleNavigate = (e) => {
    if (e.key === 'Enter') {
      let finalUrl = url.trim();
      if (!finalUrl.startsWith('http://') && !finalUrl.startsWith('https://') && !finalUrl.startsWith('file://')) {
        finalUrl = 'https://' + finalUrl;
      }
      setUrl(finalUrl);
      // If electron is available, use it. Otherwise use the agent.
      if (window.electronAPI) {
        window.electronAPI.navigateTo(finalUrl);
      }
    }
  };

  const handleScanPage = async () => {
    try {
      if (window.electronAPI && window.electronAPI.toggleDashboard) {
        window.electronAPI.toggleDashboard(true);
      }
      const targetUrl = url || 'http://example.com';
      navigate('/dashboard', { state: { triggerScanUrl: targetUrl } });
    } catch (err) {
      console.error("Failed to navigate to dashboard:", err);
    }
  };

  const handleSendGoal = async () => {
    const goal = agentGoal.trim();
    if (!goal) return;

    try {
      setIsAgentRunning(true);
      // Send goal directly to backend via HTTP — works without Electron
      const response = await fetch('http://localhost:8000/api/agent/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ goal }),
      });
      if (!response.ok) {
        console.error("Agent start failed:", await response.text());
        setIsAgentRunning(false);
      }
      setAgentGoal('');
    } catch (err) {
      console.error("Failed to start agent:", err);
      setIsAgentRunning(false);
    }
  };

  const handleStopAgent = async () => {
    try {
      await fetch('http://localhost:8000/api/agent/stop', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}',
      });
      setIsAgentRunning(false);
    } catch (err) {
      console.error("Failed to stop agent:", err);
    }
  };

  const handleClearSession = async () => {
    if (isAgentRunning) return;
    try {
      await fetch('http://localhost:8000/api/agent/clear', {
        method: 'POST',
      });
      setUrl('');
      setAgentGoal('');
    } catch (err) {
      console.error("Failed to clear agent session:", err);
    }
  };

  const openDashboard = () => {
    if (window.electronAPI && window.electronAPI.toggleDashboard) {
      window.electronAPI.toggleDashboard(true);
    }
    navigate('/dashboard');
  };

  return (
    <div className="browser-ui-container">
      <header className="command-bar">
        <div className="command-bar-left">
          <div className="logo"><Shield size={24} color="#06b6d4" /></div>
          <div className="address-bar">
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              onKeyDown={handleNavigate}
              placeholder="Enter URL or search..."
              spellCheck="false"
            />
            <button className="scan-btn" onClick={handleScanPage}>Scan</button>
          </div>
        </div>

        <div className="command-bar-center">
          <div className="agent-input-wrap">
            <input
              type="text"
              value={agentGoal}
              onChange={(e) => setAgentGoal(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSendGoal()}
              placeholder="Ask the agent anything... (e.g., 'Find cheap flights')"
              disabled={isAgentRunning}
            />
            {!isAgentRunning ? (
              <button onClick={handleSendGoal} disabled={!agentGoal.trim()} className="agent-btn">
                <Send size={18} />
              </button>
            ) : (
              <button onClick={handleStopAgent} className="agent-btn stop-btn-visible">
                <Square size={18} />
              </button>
            )}
          </div>
        </div>

        <div className="command-bar-right">
          <div className={`status-indicator ${isBackendConnected ? 'connected' : 'disconnected'}`}>
            <span className="dot"></span>
            <span className="label">{isBackendConnected ? 'Online' : 'Offline'}</span>
          </div>
          {isAgentRunning && (
            <div className="agent-running-badge">
              <Loader size={14} className="spin" />
              Agent Running
            </div>
          )}
          <div className={`risk-badge ${riskLevel.toLowerCase()}`}>
            <span>🛡️ {riskLevel}</span>
          </div>
          
          {/* New Task / Clear Button */}
          {(!isAgentRunning && (liveFrame || stepsLog.length > 0)) && (
            <button onClick={handleClearSession} className="dashboard-btn" style={{color: 'var(--text-secondary)'}} title="Clear session and start fresh">
              <Trash2 size={20} /> Clear
            </button>
          )}

          <button onClick={openDashboard} className="dashboard-btn" title="Open Security Dashboard">
            <LayoutDashboard size={20} /> Dashboard
          </button>
        </div>
      </header>

      <main className="main-content">
        {/* HITL Approval Modal */}
        {hitlRequest && (
          <HITLApproval
            data={hitlRequest}
            onRespond={(approved) => respondToHitl(hitlRequest.requestId, approved)}
          />
        )}

        {/* Agent is idle — show welcome */}
        {(!isAgentRunning && !liveFrame && agentStatus === 'idle') && (
          <div className="welcome-screen">
            <h1>Secure Agentic Browser</h1>
            <p>Type a goal above and the agent will browse securely for you.</p>
            <p style={{fontSize: '0.85rem', marginTop: '1rem', color: 'var(--text-secondary)'}}>
              Try: "Go to wikipedia.org and find out what today's featured article is"
            </p>
          </div>
        )}

        {/* Agent is active or has results — show the live view */}
        {(isAgentRunning || liveFrame || agentStatus === 'finished' || agentStatus === 'failed') && (
          <div className="agent-live-view">
            {/* Left panel: steps log */}
            <div className="agent-steps-panel">
              <div className="steps-header">
                <Brain size={16} /> Agent Steps
              </div>
              <div className="steps-list">
                {stepsLog.map((s, i) => {
                  const Icon = ACTION_ICONS[s.actionType] || Brain;
                  const color = STATUS_COLORS[s.status] || '#6b7280';
                  return (
                    <div key={i} className="step-item" style={{borderLeftColor: color}}>
                      <div className="step-header">
                        <Icon size={14} style={{color}} />
                        <span className="step-num">Step {s.step}</span>
                        <span className="step-action" style={{color}}>{s.actionType}</span>
                      </div>
                      <div className="step-reasoning">{s.reasoning?.slice(0, 120)}</div>
                      {s.detail && <div className="step-detail">{s.detail}</div>}
                    </div>
                  );
                })}
                {isAgentRunning && (
                  <div className="step-item thinking">
                    <Loader size={14} className="spin" style={{color: '#f59e0b'}} />
                    <span>Thinking...</span>
                  </div>
                )}
              </div>
            </div>

            {/* Center: LIVE browser stream */}
            <div className="agent-browser-view">
              <div className="browser-chrome">
                <div className="browser-dots">
                  <span className="dot-red"></span>
                  <span className="dot-yellow"></span>
                  <span className="dot-green"></span>
                </div>
                <div className="browser-url-display">
                  {currentUrl && currentUrl !== 'about:blank' ? currentUrl : 'Navigating...'}
                </div>
                {isAgentRunning && (
                  <div className="live-indicator">
                    <span className="live-dot"></span> LIVE
                  </div>
                )}
                {stepInfo && (
                  <div className="browser-status-pill" style={{background: STATUS_COLORS[stepInfo.status] || '#6b7280'}}>
                    {stepInfo.status}
                  </div>
                )}
              </div>
              <div className="browser-viewport">
                {liveFrame ? (
                  <img
                    src={`data:image/jpeg;base64,${liveFrame}`}
                    alt="Live browser view"
                    className="agent-screenshot live-stream"
                  />
                ) : (
                  <div className="screenshot-placeholder">
                    {isAgentRunning ? (
                      <>
                        <Loader size={48} className="spin" style={{color: 'var(--text-secondary)', opacity: 0.5}} />
                        <p>Connecting to live browser stream...</p>
                      </>
                    ) : (
                      <>
                        <Globe size={48} style={{color: 'var(--text-secondary)', opacity: 0.3}} />
                        <p>Agent will show the page here...</p>
                      </>
                    )}
                  </div>
                )}
              </div>
            </div>

            {/* Right: current step detail */}
            <div className="agent-info-panel">
              <div className="info-section">
                <h4>Current Goal</h4>
                <p className="goal-text">{dashboardData?.currentGoal || 'Starting...'}</p>
              </div>
              {stepInfo && (
                <div className="info-section">
                  <h4>Last Action</h4>
                  <div className="action-badge" style={{color: STATUS_COLORS[stepInfo.status]}}>
                    {stepInfo.actionType} {stepInfo.detail ? `→ ${stepInfo.detail.slice(0, 40)}` : ''}
                  </div>
                </div>
              )}
              <div className="info-section">
                <h4>Status</h4>
                <div className="status-text" style={{color: STATUS_COLORS[agentStatus]}}>
                  {agentStatus === 'finished' && <CheckCircle size={16} />}
                  {agentStatus === 'failed' && <XCircle size={16} />}
                  {isAgentRunning && <Loader size={16} className="spin" />}
                  {agentStatus}
                </div>
              </div>
              {stepInfo && (
                <div className="info-section">
                  <h4>Progress</h4>
                  <div className="progress-bar">
                    <div className="progress-fill" style={{width: `${(stepInfo.step / stepInfo.maxSteps) * 100}%`}}></div>
                  </div>
                  <span className="progress-label">{stepInfo.step} / {stepInfo.maxSteps}</span>
                </div>
              )}
              <div className="info-section">
                <h4>Risk Score</h4>
                <div className={`risk-score ${riskLevel.toLowerCase()}`}>{globalRisk} / 100</div>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
};

export default BrowserUI;