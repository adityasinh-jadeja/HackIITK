import React, { useEffect, useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useWebSocket } from '../hooks/useWebSocket';
import './Dashboard.css';

const Dashboard = () => {
    const navigate = useNavigate();
    const location = useLocation();
    const { connected, dashboardData: liveData } = useWebSocket();
    const [localScanning, setLocalScanning] = useState(false);

    useEffect(() => {
        if (location.state?.triggerScanUrl) {
            setLocalScanning(true);
            const triggerUrl = location.state.triggerScanUrl;
            
            // Clear the location state so it doesn't re-trigger on remount
            window.history.replaceState({}, document.title)

            fetch('http://localhost:8000/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: triggerUrl })
            }).then(() => {
                setLocalScanning(false);
            }).catch(err => {
                console.error(err);
                setLocalScanning(false);
            });
        }
    }, [location.state]);

    // Fallback data when initial load happens or disconnected
    const data = liveData || {
        url: "Waiting for navigation...",
        overallRisk: 0,
        currentGoal: "Waiting for agent command...",
        agentStatus: "idle",
        metrics: {
            blocked: 0,
            allowed: 0,
            overrides: 0,
            latency: 0.0
        },
        threats: [],
        riskBreakdown: {
            promptInjection: 0,
            domAnomalies: 0,
            networkAnomaly: 0,
            uiDeception: 0,
            goalAlignment: 100
        },
        llmExplanation: "System initialized. Sandbox isolated. Awaiting navigation or agent instruction."
    };

    const globalRisk = data.overallRisk || 0;
    // In Phase 1, dashboardData from WS gives us basic info.
    // For missing properties (like riskBreakdown), we provide defaults.
    const riskBreakdown = data.riskBreakdown || {
        promptInjection: 0, domAnomalies: 0, networkAnomaly: 0, uiDeception: 0, goalAlignment: 100
    };
    const sessionMetrics = data.metrics || { blocked: 0, allowed: 0 };
    const threats = data.threats || [];

    const closeDashboard = () => {
        if (window.electronAPI) {
             window.electronAPI.toggleDashboard(false);
        }
        navigate('/');
    };

    return (
        <div className="dashboard-layout">
            {/* TOP BAR */}
            <header className="dash-topbar">
                <div className="dash-logo">
                    <span className={`status-dot ${connected ? 'green' : 'red'}`}></span>
                    <h2>SecureAgent Browser</h2>
                </div>
                
                <div className="dash-url-bar">
                    {data.url || "FastAPI Backend"}
                </div>

                <div className="dash-top-actions">
                    <div className={`risk-pill ${globalRisk > 40 ? 'warning' : globalRisk > 70 ? 'danger' : 'safe'}`}>
                        Risk: {globalRisk} / 100
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
                                <div className="llm-model">gemini-flash</div>
                            </div>
                            <div className="llm-badge">
                                <div><span className="status-dot green"></span> <strong>Task LLM</strong></div>
                                <div className="llm-model">gemini-flash</div>
                            </div>
                        </div>
                    </section>

                    <section className="dash-section">
                        <h3 className="section-title">CURRENT GOAL</h3>
                        <div className="goal-card">
                            <div className="goal-status-text">{data.agentStatus === 'idle' ? 'Idle' : 'Task in progress'}</div>
                            <h4 className="goal-title">{data.currentGoal}</h4>
                            <div className="goal-step">{data.agentStatus}</div>
                            <div className="progress-bar-bg">
                                <div className="progress-bar-fill green-fill" style={{width: data.agentStatus === 'idle' ? '0%' : '50%'}}></div>
                            </div>
                        </div>
                    </section>

                    <section className="dash-section">
                        <h3 className="section-title">RISK BREAKDOWN</h3>
                        <div className="risk-list">
                            <RiskItem label="Prompt injection" value={riskBreakdown.promptInjection} colorClass="red" />
                            <RiskItem label="DOM anomalies" value={riskBreakdown.domAnomalies} colorClass="orange" />
                            <RiskItem label="Network anomaly" value={riskBreakdown.networkAnomaly} colorClass="blue" />
                            <RiskItem label="UI deception" value={riskBreakdown.uiDeception} colorClass="orange" />
                            <RiskItem label="Goal alignment" value={riskBreakdown.goalAlignment} colorClass="green" />
                        </div>
                    </section>

                    <section className="dash-section session-metrics-section">
                        <h3 className="section-title">SESSION METRICS</h3>
                        <div className="metrics-grid">
                            <div className="metric-box">
                                <span className="metric-val red-text">{sessionMetrics.blocked}</span>
                                <span className="metric-label">blocked</span>
                            </div>
                            <div className="metric-box">
                                <span className="metric-val green-text">{sessionMetrics.allowed}</span>
                                <span className="metric-label">allowed</span>
                            </div>
                            {/* Dummy boxes to match design */}
                            <div className="metric-box">
                                <span className="metric-val text-yellow">{threats.length}</span>
                            </div>
                            <div className="metric-box">
                                <span className="metric-val text-white">{globalRisk > 0 ? '0.91' : '0.00'}</span>
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
                            <div className="preview-url">{(data.url || '').replace(/^https?:\/\//, '')}</div>
                        </div>
                        <div className="preview-body">
                            {threats.length > 0 ? (
                                <>
                                    <div className="preview-warning-outline">
                                        <span className="warning-label">{threats[0].severity || threats[0].level || 'CRITICAL'}: Page Flagged</span>
                                        <h2>Security Intercept</h2>
                                    </div>
                                    <p className="preview-desc">The active session has encountered potentially unsafe elements dynamically during Agent execution.</p>
                                    
                                    <div className="preview-critical-box">
                                        <span className="critical-label">CRITICAL: {threats[0].type || threats[0].title}</span>
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
                            <span className={`big-score ${globalRisk > 40 ? 'orange-text' : 'green-text'}`}>{globalRisk}</span>
                            <span className="score-label">overall risk score</span>
                        </div>
                        <div className="policy-decision">
                            <span className={`decision-text ${globalRisk > 40 ? 'warning-text' : 'green-text'}`}>
                                {globalRisk > 40 ? 'CONFIRM REQUIRED' : 'ALLOW'}
                            </span>
                            <span className="score-label">policy decision</span>
                        </div>
                    </div>

                    <div className="llm-explanation">
                        <h3 className="section-title">GUARD LLM EXPLANATION</h3>
                        <p>{data.llmExplanation || "System initialized. Sandbox isolated. Awaiting navigation or agent instruction."}</p>
                        <div className="scroll-arrow-container">
                            <div className="scroll-arrow">↓</div>
                        </div>
                    </div>
                </main>

                {/* RIGHT SIDEBAR */}
                <aside className="dash-sidebar-right">
                    <section className="dash-section">
                        <h3 className="section-title">APPROVAL QUEUE</h3>
                        <div className={`approval-status ${globalRisk > 40 ? 'rejected' : 'approved'}`} style={globalRisk <= 40 ? {backgroundColor: 'rgba(74, 222, 128, 0.1)', color: 'var(--color-green)'} : {}}>
                            {globalRisk > 40 ? 'Action blocked by operator' : 'All actions permitted'}
                        </div>
                    </section>

                    <section className="dash-section">
                        <h3 className="section-title">DETECTED THREATS</h3>
                        <div className="threats-list">
                            {threats.length === 0 ? (
                                <p style={{color: 'var(--text-secondary)', fontSize: '0.85rem'}}>No threats logged.</p>
                            ) : threats.map((threat, idx) => (
                                <ThreatCard key={idx} threat={threat} />
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
  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...props}>
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

const ThreatCard = ({ threat }) => {
    const [expanded, setExpanded] = React.useState(false);
    return (
        <div className={`threat-card border-${(threat.severity || 'high').toLowerCase()}`}>
            <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center'}}>
                <h4>{threat.type || 'Unknown Threat'}</h4>
                <span className={`risk-pill ${(threat.severity || 'high').toLowerCase()}`} style={{fontSize: '0.7rem', padding: '2px 6px'}}>
                    {threat.severity?.toUpperCase() || 'HIGH'}
                </span>
            </div>
            <p>{threat.description}</p>
            <p style={{fontSize: '0.8rem', color: '#999', marginTop: '4px'}}>
                <strong>Confidence:</strong> {Math.round((threat.confidence || 1) * 100)}%
                <br/><strong>XPath:</strong> <span style={{fontFamily: 'monospace', color: '#ccc'}}>{threat.element_xpath || 'N/A'}</span>
            </p>
            {threat.element_html && (
                <div style={{marginTop: '0.5rem'}}>
                    <button onClick={() => setExpanded(!expanded)} style={{fontSize: '0.75rem', cursor: 'pointer', background: 'transparent', border: '1px solid #444', color: '#ccc', borderRadius: '4px', padding: '2px 8px'}}>
                        {expanded ? 'Hide HTML' : 'View Raw HTML'}
                    </button>
                    {expanded && (
                        <pre style={{background: '#1e1e1e', padding: '0.5rem', borderRadius: '4px', marginTop: '0.5rem', fontSize: '0.75rem', overflowX: 'auto', color: '#a6e22e', borderLeft: '2px solid #3b82f6'}}>
                            {threat.element_html}
                        </pre>
                    )}
                </div>
            )}
        </div>
    );
};

export default Dashboard;