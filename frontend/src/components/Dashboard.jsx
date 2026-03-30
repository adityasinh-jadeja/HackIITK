import React, { useEffect, useState, useCallback } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useWebSocket } from '../hooks/useWebSocket';
import HITLApproval from './HITLApproval';
import './Dashboard.css';

const Dashboard = () => {
    const navigate = useNavigate();
    const location = useLocation();
    const { connected, dashboardData: liveData, hitlRequest, respondToHitl, clearState } = useWebSocket();
    const [localScanning, setLocalScanning] = useState(false);
    const [activeTab, setActiveTab] = useState('preview');

    useEffect(() => {
        if (location.state?.triggerScanUrl) {
            // Clear previous scan data immediately so old results don't persist
            clearState();
            setLocalScanning(true);
            const triggerUrl = location.state.triggerScanUrl;
            
            // Clear the location state so it doesn't re-trigger on remount
            window.history.replaceState({}, document.title)

            fetch('http://localhost:8000/api/evaluate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: triggerUrl, goal: 'General browsing' })
            }).then(() => {
                setLocalScanning(false);
            }).catch(err => {
                console.error(err);
                setLocalScanning(false);
            });
        }
    }, [location.state, clearState]);

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
        llmVerdict: null,
        policyDecision: null,
    };

    const globalRisk = data.overallRisk || 0;
    const sessionMetrics = data.metrics || { blocked: 0, allowed: 0, overrides: 0, latency: 0 };
    const threats = data.threats || [];
    const llmVerdict = data.llmVerdict || null;
    const policyDecision = data.policyDecision || null;
    const policyAction = policyDecision?.action || data.action || (globalRisk > 65 ? 'REQUIRE_APPROVAL' : globalRisk > 40 ? 'WARN' : 'ALLOW');

    const closeDashboard = () => {
        if (window.electronAPI) {
             window.electronAPI.toggleDashboard(false);
        }
        navigate('/');
    };

    const handleHitlRespond = useCallback((requestId, approved) => {
        respondToHitl(requestId, approved);
    }, [respondToHitl]);

    // Classification badge color
    const classificationColor = (cls) => {
        if (cls === 'safe') return 'green';
        if (cls === 'suspicious') return 'yellow';
        if (cls === 'malicious') return 'red';
        return 'blue';
    };

    // Policy action badge color
    const actionColor = (action) => {
        if (action === 'ALLOW') return 'green';
        if (action === 'WARN') return 'yellow';
        if (action === 'REQUIRE_APPROVAL') return 'orange';
        if (action === 'BLOCK') return 'red';
        return 'blue';
    };

    return (
        <div className="dashboard-layout">
            {/* HITL Approval Modal */}
            <HITLApproval hitlRequest={hitlRequest} onRespond={handleHitlRespond} />

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
                    <div className={`risk-pill ${globalRisk >= 85 ? 'danger' : globalRisk >= 40 ? 'warning' : 'safe'}`}>
                        Risk: {Math.round(globalRisk)} / 100
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
                            <div className="goal-step">{
                                data.agentStatus === 'rendering' ? '🌐 Rendering page...' :
                                data.agentStatus === 'scanning' ? '🔍 DOM Scanning...' :
                                data.agentStatus === 'llm_analysis' ? '🤖 Guard LLM analyzing...' :
                                data.agentStatus === 'evaluation_complete' ? '✅ Evaluation complete' :
                                data.agentStatus
                            }</div>
                            <div className="progress-bar-bg">
                                <div className="progress-bar-fill green-fill" style={{width: 
                                    data.agentStatus === 'rendering' ? '25%' :
                                    data.agentStatus === 'scanning' ? '50%' :
                                    data.agentStatus === 'llm_analysis' ? '75%' :
                                    data.agentStatus === 'evaluation_complete' ? '100%' :
                                    '0%'
                                }}></div>
                            </div>
                        </div>
                    </section>

                    {/* RISK BREAKDOWN — Phase 3 enhanced */}
                    <section className="dash-section">
                        <h3 className="section-title">RISK BREAKDOWN</h3>
                        <div className="risk-list">
                            <RiskItem label="DOM Scanner" value={policyDecision?.dom_score || 0} colorClass="red" />
                            <RiskItem label="Guard LLM" value={policyDecision?.llm_score || 0} colorClass="orange" />
                            <RiskItem label="Heuristic" value={policyDecision?.heuristic_score || 0} colorClass="blue" />
                            <RiskItem label="Goal Alignment" value={llmVerdict ? Math.round(llmVerdict.goal_alignment * 100) : 100} colorClass="green" />
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
                            <div className="metric-box">
                                <span className="metric-val text-yellow">{sessionMetrics.overrides || 0}</span>
                                <span className="metric-label">overrides</span>
                            </div>
                            <div className="metric-box">
                                <span className="metric-val text-white">{data.latency ? `${Math.round(data.latency)}ms` : '—'}</span>
                                <span className="metric-label">latency</span>
                            </div>
                        </div>
                    </section>
                </aside>

                {/* CENTER CONTENT */}
                <main className="dash-center">
                    <div className="center-tabs">
                        <div className={`tab ${activeTab === 'preview' ? 'active' : ''}`} onClick={() => setActiveTab('preview')}>Page<br/>preview</div>
                        <div className={`tab ${activeTab === 'timeline' ? 'active' : ''}`} onClick={() => setActiveTab('timeline')}>Session<br/>timeline</div>
                        <div className={`tab ${activeTab === 'network' ? 'active' : ''}`} onClick={() => setActiveTab('network')}>Network<br/>log</div>
                        <div className={`tab ${activeTab === 'guard' ? 'active' : ''}`} onClick={() => setActiveTab('guard')}>Guard<br/>LLM report</div>
                    </div>

                    {activeTab === 'preview' && (
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
                                {localScanning ? (
                                    <div style={{textAlign: 'center', color: 'var(--text-secondary)', padding: '2rem'}}>
                                        <div className="scanning-spinner">⏳</div>
                                        <h3>Scanning...</h3>
                                        <p>Running security evaluation through DOM Scanner → Guard LLM → Policy Engine</p>
                                    </div>
                                ) : policyAction === 'ALLOW' || policyAction === 'WARN' ? (
                                    <div style={{textAlign: 'center', color: 'var(--text-secondary)', padding: '2rem'}}>
                                        <ShieldIcon style={{opacity: 0.3, width: '48px', height: '48px', marginBottom: '1rem'}} />
                                        <h3 style={{color: policyAction === 'ALLOW' ? 'var(--color-green)' : 'var(--color-yellow)'}}>
                                            {policyAction === 'ALLOW' ? '✅ Page Approved' : '⚠️ Proceed with Caution'}
                                        </h3>
                                        <p>{policyDecision?.reason || 'No active threats that require intervention.'}</p>
                                    </div>
                                ) : threats.length > 0 ? (
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
                    )}

                    {activeTab === 'guard' && (
                        <div className="guard-llm-report">
                            {llmVerdict ? (
                                <>
                                    <div className="verdict-header-row">
                                        <span className={`verdict-badge verdict-${classificationColor(llmVerdict.classification)}`}>
                                            {llmVerdict.classification?.toUpperCase()}
                                        </span>
                                        <span className="verdict-confidence">
                                            Confidence: {Math.round(llmVerdict.confidence * 100)}%
                                        </span>
                                    </div>
                                    <div className="verdict-explanation-card">
                                        <h4>LLM Explanation</h4>
                                        <p>{llmVerdict.explanation}</p>
                                    </div>
                                    <div className="verdict-metrics-row">
                                        <div className="verdict-metric">
                                            <span className="verdict-metric-value">{Math.round(llmVerdict.goal_alignment * 100)}%</span>
                                            <span className="verdict-metric-label">Goal Alignment</span>
                                        </div>
                                        <div className="verdict-metric">
                                            <span className="verdict-metric-value">{llmVerdict.recommended_action?.toUpperCase()}</span>
                                            <span className="verdict-metric-label">Recommended Action</span>
                                        </div>
                                    </div>
                                </>
                            ) : (
                                <div style={{textAlign: 'center', color: 'var(--text-secondary)', padding: '3rem'}}>
                                    <p>No Guard LLM report available yet. Trigger a security evaluation to see results.</p>
                                </div>
                            )}
                        </div>
                    )}

                    {(activeTab === 'timeline' || activeTab === 'network') && (
                        <div style={{textAlign: 'center', color: 'var(--text-secondary)', padding: '3rem'}}>
                            <p>Coming in Phase 5 — Agent pipeline will populate this view.</p>
                        </div>
                    )}

                    <div className="center-bottom-stats">
                        <div className="risk-score-display">
                            <span className={`big-score ${globalRisk >= 65 ? 'red-text' : globalRisk >= 40 ? 'orange-text' : 'green-text'}`}>{Math.round(globalRisk)}</span>
                            <span className="score-label">overall risk score</span>
                        </div>
                        <div className="policy-decision">
                            <span className={`decision-text ${actionColor(policyAction)}-text`}>
                                {policyAction}
                            </span>
                            <span className="score-label">policy decision</span>
                        </div>
                    </div>

                    <div className="llm-explanation">
                        <h3 className="section-title">GUARD LLM EXPLANATION</h3>
                        <p>{llmVerdict?.explanation || "System initialized. Sandbox isolated. Awaiting navigation or agent instruction."}</p>
                        <div className="scroll-arrow-container">
                            <div className="scroll-arrow">↓</div>
                        </div>
                    </div>
                </main>

                {/* RIGHT SIDEBAR */}
                <aside className="dash-sidebar-right">
                    <section className="dash-section">
                        <h3 className="section-title">POLICY DECISION</h3>
                        <div className={`approval-status ${policyAction === 'ALLOW' ? 'approved' : policyAction === 'BLOCK' ? 'rejected' : 'pending'}`}
                             style={policyAction === 'ALLOW' ? {backgroundColor: 'rgba(74, 222, 128, 0.1)', color: 'var(--color-green)'} : 
                                    policyAction === 'WARN' ? {backgroundColor: 'rgba(234, 179, 8, 0.1)', color: 'var(--color-yellow)'} :
                                    policyAction === 'REQUIRE_APPROVAL' ? {backgroundColor: 'rgba(249, 115, 22, 0.1)', color: 'var(--color-orange)'} : {}}>
                            {policyAction === 'ALLOW' ? '✅ All actions permitted' :
                             policyAction === 'WARN' ? '⚠️ Proceed with caution' :
                             policyAction === 'REQUIRE_APPROVAL' ? '🔶 Awaiting operator approval' :
                             '❌ Action blocked'}
                        </div>
                        {policyDecision && (
                            <div className="policy-reason-text" style={{marginTop: '0.75rem', fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: '1.4'}}>
                                {policyDecision.reason}
                            </div>
                        )}
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
            <span>{Math.round(value)}</span>
        </div>
        <div className="progress-bar-bg small">
            <div className={`progress-bar-fill ${colorClass}-fill`} style={{ width: `${Math.min(100, value)}%` }}></div>
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