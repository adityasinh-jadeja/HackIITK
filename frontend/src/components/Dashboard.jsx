import React, { useState, useEffect } from 'react';
import './Dashboard.css';

const Dashboard = () => {
    // Initial static mock data
    const initialData = {
        url: "https://shop.example.com/checkout",
        globalRisk: 47,
        goal: {
            title: "Waiting for agent command...",
            step: "Idle",
            progress: 0
        },
        riskBreakdown: {
            promptInjection: 0,
            domAnomalies: 0,
            networkAnomaly: 0,
            uiDeception: 0,
            goalAlignment: 100
        },
        sessionMetrics: {
            blocked: 0,
            allowed: 0
        },
        threats: [],
        llmExplanation: "System initialized. Sandbox isolated. Awaiting navigation or agent instruction."
    };

    const [dashboardData, setDashboardData] = useState(initialData);

    useEffect(() => {
        const fetchDashboardData = async () => {
            try {
                const response = await fetch('http://localhost:5000/api/dashboard');
                if (response.ok) {
                    const data = await response.json();
                    setDashboardData(prev => ({
                        ...prev,
                        globalRisk: data.overallRisk ?? prev.globalRisk,
                        goal: {
                            ...prev.goal,
                            title: data.currentGoal || prev.goal.title,
                            progress: data.currentGoal && data.currentGoal !== "Waiting for agent command..." ? 50 : 0
                        },
                        sessionMetrics: {
                            ...prev.sessionMetrics,
                            blocked: data.metrics?.blocked ?? prev.sessionMetrics.blocked,
                            allowed: data.metrics?.allowed ?? prev.sessionMetrics.allowed
                        },
                        threats: data.threats ? data.threats.map(t => ({
                            title: t.title,
                            level: t.severity || 'CRITICAL',
                            detail: t.desc || 'Detected threat on the page'
                        })) : prev.threats
                    }));
                }
            } catch (err) {
                console.error("Dashboard fetch error:", err);
            }
        };

        // Fetch immediately and set up polling
        fetchDashboardData();
        const intervalId = setInterval(fetchDashboardData, 3000);

        if (window.electronAPI) {
            // Listen for simulated updates from the Main Process
            const cleanup = window.electronAPI.onBackendMessage((message) => {  
                if (message && message.type === 'DASHBOARD_UPDATE') {
                    setDashboardData(prev => ({
                        ...prev,
                        ...message.payload
                    }));
                }
            });
            return () => {
                clearInterval(intervalId);
                cleanup();
            };
        }
        
        return () => clearInterval(intervalId);
    }, []);

    const closeDashboard = () => {
        if (window.electronAPI) {
             window.electronAPI.toggleDashboard(false);
             window.location.hash = '/';
        } else {
             window.location.hash = '/';
        }
    };

    return (
        <div className="dashboard-layout">
            {/* TOP BAR */}
            <header className="dash-topbar">
                <div className="dash-logo">
                    <span className="status-dot green"></span>
                    <h2>SecureAgent Browser</h2>
                </div>
                
                <div className="dash-url-bar">
                    {dashboardData.url}
                </div>

                <div className="dash-top-actions">
                    <div className={`risk-pill ${dashboardData.globalRisk > 40 ? 'warning' : dashboardData.globalRisk > 70 ? 'danger' : 'safe'}`}>
                        Risk: {dashboardData.globalRisk} / 100
                    </div>
                    <button className="btn-next" onClick={closeDashboard}>Return to Session</button>
                </div>
            </header>

            <div className="dash-main-grid">
                {/* LEFT SIDEBAR */}
                <aside className="dash-sidebar-left">
                    <section className="dash-section">
                        <h3 className="section-title">DUAL LLM STATUS</h3>
                        <div className="llm-status-row">
                            <div className="llm-badge">
                                <div><span className="status-dot green"></span> <strong>Guard LLM</strong></div>
                                <div className="llm-model">claude-sonnet</div>
                            </div>
                            <div className="llm-badge">
                                <div><span className="status-dot green"></span> <strong>Task LLM</strong></div>
                                <div className="llm-model">claude-haiku</div>
                            </div>
                        </div>
                    </section>

                    <section className="dash-section">
                        <h3 className="section-title">CURRENT GOAL</h3>
                        <div className="goal-card">
                            <div className="goal-status-text">{dashboardData.goal.progress > 0 ? "Task in progress" : "Idle"}</div>
                            <h4 className="goal-title">{dashboardData.goal.title}</h4>
                            <div className="goal-step">{dashboardData.goal.step}</div>
                            <div className="progress-bar-bg">
                                <div className="progress-bar-fill green-fill" style={{width: `${dashboardData.goal.progress}%`}}></div>
                            </div>
                        </div>
                    </section>

                    <section className="dash-section">
                        <h3 className="section-title">RISK BREAKDOWN</h3>
                        <div className="risk-list">
                            <RiskItem label="Prompt injection" value={dashboardData.riskBreakdown.promptInjection} colorClass="red" />
                            <RiskItem label="DOM anomalies" value={dashboardData.riskBreakdown.domAnomalies} colorClass="orange" />
                            <RiskItem label="Network anomaly" value={dashboardData.riskBreakdown.networkAnomaly} colorClass="blue" />
                            <RiskItem label="UI deception" value={dashboardData.riskBreakdown.uiDeception} colorClass="orange" />
                            <RiskItem label="Goal alignment" value={dashboardData.riskBreakdown.goalAlignment} colorClass="green" />
                        </div>
                    </section>

                    <section className="dash-section session-metrics-section">
                        <h3 className="section-title">SESSION METRICS</h3>
                        <div className="metrics-grid">
                            <div className="metric-box">
                                <span className="metric-val red-text">{dashboardData.sessionMetrics.blocked}</span>
                                <span className="metric-label">blocked</span>
                            </div>
                            <div className="metric-box">
                                <span className="metric-val green-text">{dashboardData.sessionMetrics.allowed}</span>
                                <span className="metric-label">allowed</span>
                            </div>
                            {/* Dummy boxes to match design */}
                            <div className="metric-box">
                                <span className="metric-val text-yellow">{dashboardData.threats.length}</span>
                            </div>
                            <div className="metric-box">
                                <span className="metric-val text-white">{dashboardData.globalRisk > 0 ? '0.91' : '0.00'}</span>
                            </div>
                        </div>
                    </section>
                </aside>

                {/* CENTER CONTENT */}
                <main className="dash-center">
                    <div className="center-tabs">
                        <div className="tab active">Page<br/>preview</div>
                        <div className="tab">Session<br/>timeline</div>
                        <div className="tab">Network<br/>log</div>
                        <div className="tab">Guard<br/>LLM report</div>
                    </div>

                    <div className="browser-preview-frame">
                        <div className="preview-header">
                            <div className="mac-dots">
                                <span className="dot red"></span>
                                <span className="dot yellow"></span>
                                <span className="dot green"></span>
                            </div>
                            <div className="preview-url">{dashboardData.url.replace(/^https?:\/\//, '')}</div>
                        </div>
                        <div className="preview-body">
                            {dashboardData.threats.length > 0 ? (
                                <>
                                    <div className="preview-warning-outline">
                                        <span className="warning-label">{dashboardData.threats[0].level}: Page Flagged</span>
                                        <h2>Security Intercept</h2>
                                    </div>
                                    <p className="preview-desc">The active session has encountered potentially unsafe elements dynamically during Agent execution.</p>
                                    
                                    <div className="preview-critical-box">
                                        <span className="critical-label">CRITICAL: {dashboardData.threats[0].title}</span>
                                        <div className="critical-line"></div>
                                    </div>
                                </>
                            ) : (
                                <div style={{textAlign: 'center', color: 'var(--text-secondary)', padding: '2rem'}}>
                                    <ShieldIcon style={{opacity: 0.3, width: '48px', height: '48px', marginBottom: '1rem'}} />
                                    <h3>Page Currently Safe</h3>
                                    <p>No active threats detected on the current DOM.</p>
                                </div>
                            )}
                        </div>
                    </div>

                    <div className="center-bottom-stats">
                        <div className="risk-score-display">
                            <span className={`big-score ${dashboardData.globalRisk > 40 ? 'orange-text' : 'green-text'}`}>{dashboardData.globalRisk}</span>
                            <span className="score-label">overall risk score</span>
                        </div>
                        <div className="policy-decision">
                            <span className={`decision-text ${dashboardData.globalRisk > 40 ? 'warning-text' : 'green-text'}`}>
                                {dashboardData.globalRisk > 40 ? 'CONFIRM REQUIRED' : 'ALLOW'}
                            </span>
                            <span className="score-label">policy decision</span>
                        </div>
                    </div>

                    <div className="llm-explanation">
                        <h3 className="section-title">GUARD LLM EXPLANATION</h3>
                        <p>{dashboardData.llmExplanation}</p>
                        <div className="scroll-arrow-container">
                            <div className="scroll-arrow">↓</div>
                        </div>
                    </div>
                </main>

                {/* RIGHT SIDEBAR */}
                <aside className="dash-sidebar-right">
                    <section className="dash-section">
                        <h3 className="section-title">APPROVAL QUEUE</h3>
                        <div className={`approval-status ${dashboardData.globalRisk > 40 ? 'rejected' : 'approved'}`} style={dashboardData.globalRisk <= 40 ? {backgroundColor: 'rgba(74, 222, 128, 0.1)', color: 'var(--color-green)'} : {}}>
                            {dashboardData.globalRisk > 40 ? 'Action blocked by operator' : 'All actions permitted'}
                        </div>
                    </section>

                    <section className="dash-section">
                        <h3 className="section-title">DETECTED THREATS</h3>
                        <div className="threats-list">
                            {dashboardData.threats.length === 0 ? (
                                <p style={{color: 'var(--text-secondary)', fontSize: '0.85rem'}}>No threats logged.</p>
                            ) : dashboardData.threats.map((threat, idx) => (
                                <div key={idx} className={`threat-card border-${threat.level.toLowerCase()}`}>
                                    <h4>{threat.title}</h4>
                                    <p>{threat.detail} · {threat.level}</p>
                                </div>
                            ))}
                        </div>
                    </section>

                    <section className="dash-section">
                        <h3 className="section-title">SANDBOX STATUS</h3>
                        <div className="sandbox-grid">
                            <div className="sb-row"><span>Container</span> <span className="green-text">isolated</span></div>
                            <div className="sb-row"><span>Capabilities</span> <span className="green-text">cap_drop ALL</span></div>
                            <div className="sb-row"><span>Storage</span> <span className="green-text">none</span></div>
                            <div className="sb-row"><span>Session mode</span> <span className="green-text">incognito</span></div>
                        </div>
                    </section>
                </aside>
            </div>
        </div>
    );
};

// Needed an icon fallback since Lucide isn't imported for this file directly, so just an SVG:
const ShieldIcon = (props) => (
  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinelinejoin="round" {...props}>
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
  </svg>
);

const RiskItem = ({ label, value, colorClass }) => (
    <div className="risk-item">
        <div className="risk-item-header">
            <span>{label}</span>
            <span>{value}</span>
        </div>
        <div className="progress-bar-bg small">
            <div className={`progress-bar-fill ${colorClass}-fill`} style={{ width: `${value}%` }}></div>
        </div>
    </div>
);

export default Dashboard;