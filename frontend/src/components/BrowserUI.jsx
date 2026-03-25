import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, LayoutDashboard, Send, Square as StopCircle } from 'lucide-react';
import { useWebSocket } from '../hooks/useWebSocket';
import './BrowserUI.css';

const BrowserUI = () => {
  const navigate = useNavigate();
  const [url, setUrl] = useState('');
  const [agentGoal, setAgentGoal] = useState('');
  
  const { connected: isBackendConnected, dashboardData } = useWebSocket();
  const globalRisk = dashboardData?.overallRisk || 0;
  
  let riskLevel = 'Safe';
  if (globalRisk > 70) riskLevel = 'Danger';
  else if (globalRisk > 40) riskLevel = 'Warning';

  useEffect(() => {
    // Notify electron that dashboard is closed so BrowserView shows up
    if (window.electronAPI && window.electronAPI.toggleDashboard) {
      window.electronAPI.toggleDashboard(false);
    }
    
    if (window.electronAPI) {
      // Listen for Navigation Changes from main process BrowserView
      const unsubNav = window.electronAPI.onPageNavigated((data) => {
        setUrl(data.url);
      });
      return () => {
        unsubNav();
      };
    }
  }, []);

  const handleNavigate = (e) => {
    if (e.key === 'Enter' && window.electronAPI) {
      let finalUrl = url.trim();
      if (!finalUrl.startsWith('http://') && !finalUrl.startsWith('https://')) {
        finalUrl = 'https://' + finalUrl;
      }
      setUrl(finalUrl);
      window.electronAPI.navigateTo(finalUrl);
    }
  };

  const handleSendGoal = async () => {
    if (agentGoal.trim()) {
      try {
        if (window.electronAPI) {
          await window.electronAPI.sendGoal(agentGoal.trim());
        }
        setAgentGoal('');
      } catch (err) {
        console.error("Failed to start agent:", err);
      }
    }
  };

  const handleStopAgent = async () => {
    try {
      if (window.electronAPI) {
        await window.electronAPI.stopAgent();
      }
    } catch (err) {
      console.error("Failed to stop agent:", err);
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
            />
            <button onClick={handleSendGoal} disabled={!agentGoal.trim()} className="agent-btn">
              <Send size={18} />
            </button>
            <button onClick={handleStopAgent} className="agent-btn stop-btn hidden">
              <StopCircle size={18} />
            </button>
          </div>
        </div>

        <div className="command-bar-right">
          <div className={`status-indicator ${isBackendConnected ? 'connected' : 'disconnected'}`}>
            <span className="dot"></span>
            <span className="label">{isBackendConnected ? 'Online' : 'Offline'}</span>
          </div>
          <div className={`risk-badge ${riskLevel.toLowerCase()}`}>
            <span>🛡️ {riskLevel}</span>
          </div>
          <button onClick={openDashboard} className="dashboard-btn" title="Open Security Dashboard">
            <LayoutDashboard size={20} /> Dashboard
          </button>
        </div>
      </header>
      
      {/* The visible empty container behind the Electron BrowserView */}
      <main className="main-content">
        <div className="welcome-screen">
            <h1>Secure Agentic Browser</h1>
            <p>Waiting for command or navigation...</p>
        </div>
      </main>
    </div>
  );
};

export default BrowserUI;