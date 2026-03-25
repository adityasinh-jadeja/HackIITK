import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, LayoutDashboard, Send, Square as StopCircle } from 'lucide-react';
import './BrowserUI.css';

const BrowserUI = () => {
  const navigate = useNavigate();
  const [url, setUrl] = useState('');
  const [agentGoal, setAgentGoal] = useState('');
  const [isBackendConnected, setIsBackendConnected] = useState(false);
  const [riskLevel, setRiskLevel] = useState('Safe');
  const [globalRisk, setGlobalRisk] = useState(0);

  useEffect(() => {
    // Notify electron that dashboard is closed so BrowserView shows up
    if (window.electronAPI && window.electronAPI.toggleDashboard) {
      window.electronAPI.toggleDashboard(false);
    }
    
    // Poll API for risk level
    const fetchRisk = async () => {
      try {
        const response = await fetch('http://localhost:5000/api/dashboard');
        if (response.ok) {
          const data = await response.json();
          const risk = data.overallRisk || 0;
          setGlobalRisk(risk);
          if (risk > 70) setRiskLevel('Danger');
          else if (risk > 40) setRiskLevel('Warning');
          else setRiskLevel('Safe');
        }
      } catch (err) {
        // Backend not reachable
      }
    };
    fetchRisk();
    const intervalId = setInterval(fetchRisk, 3000);

    if (window.electronAPI) {
      // Listen for Navigation Changes from main process BrowserView
      const unsubNav = window.electronAPI.onPageNavigated((data) => {
        setUrl(data.url);
      });

      // Listen for Backend Status
      const unsubStatus = window.electronAPI.onBackendStatus((status) => {      
        setIsBackendConnected(status.connected);
      });

      return () => {
        clearInterval(intervalId);
        unsubNav();
        unsubStatus();
      };
    }
    return () => clearInterval(intervalId);
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

  const handleSendGoal = () => {
    if (agentGoal.trim() && window.electronAPI) {
      window.electronAPI.sendGoal(agentGoal.trim());
      setAgentGoal('');
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
            <button className="agent-btn stop-btn hidden">
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