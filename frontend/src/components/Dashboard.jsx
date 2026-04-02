import React, { useEffect, useState, useCallback } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useWebSocket } from '../hooks/useWebSocket';
import HITLApproval from './HITLApproval';
import NetworkLog from './NetworkLog';
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

    const closeDashboard = async () => {
        try {
            // Attempt to auto-clear finished/stale state when leaving the dashboard.
            // The backend safely ignores this if an agent is still actively running.
            await fetch('http://localhost:8000/api/agent/clear', { method: 'POST' });
        } catch (e) {
            console.error("Failed to clear session:", e);
        }

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
                                data.agentStatus === 'planning' ? '🧠 Agent thinking...' :
                                data.agentStatus === 'executing' ? '⚙️ Agent acting...' :
                                data.agentStatus === 'navigating' ? '🌐 Agent navigating...' :
                                data.agentStatus === 'finished' ? '✅ Agent complete' :
                                data.agentStatus === 'evaluation_complete' ? '✅ Evaluation complete' :
                                data.agentStatus
                            }</div>
                            <div className="progress-bar-bg">
                                <div className="progress-bar-fill green-fill" style={{width: 
                                    data.agentStatus === 'rendering' ? '25%' :
                                    data.agentStatus === 'scanning' ? '50%' :
                                    data.agentStatus === 'llm_analysis' ? '75%' :
                                    data.agentStatus === 'planning' ? '60%' :
                                    data.agentStatus === 'executing' ? '80%' :
                                    (data.agentStatus === 'finished' || data.agentStatus === 'evaluation_complete') ? '100%' :
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
                        <div className={`tab ${activeTab === 'preview' ? 'active' : ''}`} onClick={() => setActiveTab('preview')}>Overview</div>
                        <div className={`tab ${activeTab === 'network' ? 'active' : ''}`} onClick={() => setActiveTab('network')}>Network Log</div>
                        <div className={`tab ${activeTab === 'guard' ? 'active' : ''}`} onClick={() => setActiveTab('guard')}>Guard LLM</div>
                        <div className={`tab ${activeTab === 'timeline' ? 'active' : ''}`} onClick={() => setActiveTab('timeline')}>Timeline</div>
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
                                ) : (data.policyDecision || data.llmVerdict || data.agentStatus === 'evaluation_complete') ? (
                                    <div style={{padding: '1.5rem'}}>
                                        {/* Scan Summary Card */}
                                        <div style={{display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '1.5rem'}}>
                                            <div style={{
                                                width: '56px', height: '56px', borderRadius: '50%',
                                                display: 'flex', alignItems: 'center', justifyContent: 'center',
                                                fontSize: '1.5rem', fontWeight: 700,
                                                background: globalRisk >= 65 ? 'rgba(239,68,68,0.15)' : globalRisk >= 40 ? 'rgba(234,179,8,0.15)' : 'rgba(74,222,128,0.15)',
                                                color: globalRisk >= 65 ? 'var(--color-red)' : globalRisk >= 40 ? 'var(--color-yellow)' : 'var(--color-green)',
                                                border: `2px solid ${globalRisk >= 65 ? 'var(--color-red)' : globalRisk >= 40 ? 'var(--color-yellow)' : 'var(--color-green)'}`,
                                                flexShrink: 0,
                                            }}>
                                                {Math.round(globalRisk)}
                                            </div>
                                            <div>
                                                <h3 style={{margin: 0, color: policyAction === 'ALLOW' ? 'var(--color-green)' : policyAction === 'WARN' ? 'var(--color-yellow)' : 'var(--color-red)'}}>
                                                    {policyAction === 'ALLOW' ? '✅ Page Approved' : policyAction === 'WARN' ? '⚠️ Caution Advised' : policyAction === 'REQUIRE_APPROVAL' ? '🔶 Approval Required' : '❌ Page Blocked'}
                                                </h3>
                                                <p style={{margin: '0.25rem 0 0', color: 'var(--text-secondary)', fontSize: '0.85rem'}}>
                                                    Risk score: {Math.round(globalRisk)}/100 — Decision: {policyAction}
                                                </p>
                                            </div>
                                        </div>

                                        {/* Score Breakdown Mini-Grid */}
                                        <div style={{display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '0.75rem', marginBottom: '1.5rem'}}>
                                            <div style={{background: 'var(--bg-darker)', padding: '0.75rem', borderRadius: '8px', textAlign: 'center'}}>
                                                <div style={{fontSize: '1.3rem', fontWeight: 700, color: (policyDecision?.dom_score || 0) > 0 ? 'var(--color-red)' : 'var(--color-green)'}}>{Math.round(policyDecision?.dom_score || 0)}</div>
                                                <div style={{fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '0.2rem'}}>DOM Scanner</div>
                                            </div>
                                            <div style={{background: 'var(--bg-darker)', padding: '0.75rem', borderRadius: '8px', textAlign: 'center'}}>
                                                <div style={{fontSize: '1.3rem', fontWeight: 700, color: (policyDecision?.llm_score || 0) > 30 ? 'var(--color-orange)' : 'var(--color-green)'}}>{Math.round(policyDecision?.llm_score || 0)}</div>
                                                <div style={{fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '0.2rem'}}>Guard LLM</div>
                                            </div>
                                            <div style={{background: 'var(--bg-darker)', padding: '0.75rem', borderRadius: '8px', textAlign: 'center'}}>
                                                <div style={{fontSize: '1.3rem', fontWeight: 700, color: 'var(--color-blue)'}}>{Math.round(policyDecision?.heuristic_score || 0)}</div>
                                                <div style={{fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '0.2rem'}}>Heuristic</div>
                                            </div>
                                        </div>

                                        {/* LLM Classification */}
                                        {llmVerdict && (
                                            <div style={{background: 'var(--bg-darker)', padding: '1rem', borderRadius: '8px', borderLeft: `3px solid ${llmVerdict.classification === 'safe' ? 'var(--color-green)' : llmVerdict.classification === 'suspicious' ? 'var(--color-yellow)' : 'var(--color-red)'}`}}>
                                                <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem'}}>
                                                    <span style={{fontWeight: 600}}>Guard LLM Verdict</span>
                                                    <span style={{fontSize: '0.75rem', padding: '0.15rem 0.5rem', borderRadius: '10px',
                                                        background: llmVerdict.classification === 'safe' ? 'rgba(74,222,128,0.15)' : llmVerdict.classification === 'suspicious' ? 'rgba(234,179,8,0.15)' : 'rgba(239,68,68,0.15)',
                                                        color: llmVerdict.classification === 'safe' ? 'var(--color-green)' : llmVerdict.classification === 'suspicious' ? 'var(--color-yellow)' : 'var(--color-red)',
                                                    }}>{llmVerdict.classification?.toUpperCase()}</span>
                                                </div>
                                                <p style={{margin: 0, fontSize: '0.83rem', color: 'var(--text-secondary)', lineHeight: '1.5'}}>
                                                    {llmVerdict.explanation?.length > 200 
                                                        ? llmVerdict.explanation.substring(0, 200) + '… (see Guard LLM tab for full report)'
                                                        : llmVerdict.explanation}
                                                </p>
                                            </div>
                                        )}

                                        {/* Threats Summary */}
                                        {threats.length > 0 && (
                                            <div style={{marginTop: '1rem', padding: '0.75rem', background: 'rgba(239,68,68,0.08)', borderRadius: '8px', border: '1px solid rgba(239,68,68,0.2)'}}>
                                                <span style={{color: 'var(--color-red)', fontWeight: 600}}>⚠️ {threats.length} threat{threats.length > 1 ? 's' : ''} detected</span>
                                                <span style={{color: 'var(--text-muted)', fontSize: '0.8rem', marginLeft: '0.5rem'}}>See "Detected Threats" in sidebar →</span>
                                            </div>
                                        )}

                                        {/* Sandbox badge */}
                                        {data.sandboxed && (
                                            <div style={{marginTop: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8rem', color: 'var(--color-green)'}}>
                                                🔒 Evaluated in sandboxed environment
                                                {data.networkStats?.total_requests > 0 && (
                                                    <span style={{color: 'var(--text-muted)'}}>• {data.networkStats.total_requests} network request{data.networkStats.total_requests !== 1 ? 's' : ''} monitored</span>
                                                )}
                                            </div>
                                        )}
                                    </div>
                                ) : (
                                    <div style={{textAlign: 'center', color: 'var(--text-secondary)', padding: '2rem'}}>
                                        <ShieldIcon style={{opacity: 0.3, width: '48px', height: '48px', marginBottom: '1rem'}} />
                                        <h3>Ready to Scan</h3>
                                        <p>Enter a URL in the browser and click Scan to start a security evaluation.</p>
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

                    {activeTab === 'network' && (
                        <NetworkLog
                            networkLog={data.networkLog || []}
                            networkStats={data.networkStats || {}}
                        />
                    )}

                    {activeTab === 'timeline' && (
                        <div style={{textAlign: 'center', color: 'var(--text-secondary)', padding: '3rem'}}>
                            <p>Coming in Phase 5 — Agent pipeline will populate this view.</p>
                        </div>
                    )}


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
                                {/* Show a clean summary, not the raw debug string */}
                                DOM: {Math.round(policyDecision.dom_score || 0)} · LLM: {Math.round(policyDecision.llm_score || 0)} · Heuristic: {Math.round(policyDecision.heuristic_score || 0)}
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
                            <div className="sb-row">
                                <span>Container</span>
                                <span className="green-text">
                                    {data.sandboxStatus?.active ? '🔒 isolated' : 'idle'}
                                </span>
                            </div>
                            <div className="sb-row">
                                <span>Session</span>
                                <span className="green-text" style={{fontSize: '0.75rem', fontFamily: 'monospace'}}>
                                    {data.sandboxStatus?.sessionId
                                        ? data.sandboxStatus.sessionId.substring(0, 8) + '…'
                                        : 'none'}
                                </span>
                            </div>
                            <div className="sb-row">
                                <span>Permissions</span>
                                <span className="green-text">cap_drop ALL</span>
                            </div>
                            <div className="sb-row">
                                <span>eval()</span>
                                <span className="red-text">blocked</span>
                            </div>
                            <div className="sb-row">
                                <span>Clipboard</span>
                                <span className="red-text">blocked</span>
                            </div>
                            <div className="sb-row">
                                <span>window.open</span>
                                <span className="red-text">blocked</span>
                            </div>
                            <div className="sb-row">
                                <span>Session mode</span>
                                <span className="green-text">incognito</span>
                            </div>
                            {data.networkStats?.total_requests > 0 && (
                                <div className="sb-row">
                                    <span>Net requests</span>
                                    <span className="text-white">
                                        {data.networkStats.total_requests}
                                        {data.networkStats.blocked > 0 && (
                                            <span className="red-text" style={{marginLeft: '0.3rem'}}>
                                                ({data.networkStats.blocked} blocked)
                                            </span>
                                        )}
                                    </span>
                                </div>
                            )}
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