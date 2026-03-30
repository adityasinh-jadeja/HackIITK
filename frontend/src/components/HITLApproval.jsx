import React, { useState, useEffect, useCallback } from 'react';
import './HITLApproval.css';

const HITL_TIMEOUT_SECONDS = 60;

const HITLApproval = ({ hitlRequest, onRespond }) => {
    const [timeLeft, setTimeLeft] = useState(HITL_TIMEOUT_SECONDS);

    // Countdown timer — auto-block after timeout
    useEffect(() => {
        if (!hitlRequest) return;
        setTimeLeft(HITL_TIMEOUT_SECONDS);
        const interval = setInterval(() => {
            setTimeLeft(prev => {
                if (prev <= 1) {
                    clearInterval(interval);
                    onRespond(hitlRequest.requestId, false); // Auto-block
                    return 0;
                }
                return prev - 1;
            });
        }, 1000);
        return () => clearInterval(interval);
    }, [hitlRequest, onRespond]);

    const handleApprove = useCallback(() => {
        onRespond(hitlRequest.requestId, true);
    }, [hitlRequest, onRespond]);

    const handleBlock = useCallback(() => {
        onRespond(hitlRequest.requestId, false);
    }, [hitlRequest, onRespond]);

    if (!hitlRequest) return null;

    const { url, overallRisk, llmVerdict, policyDecision, threats } = hitlRequest;
    const riskLevel = overallRisk >= 85 ? 'high' : overallRisk >= 65 ? 'medium' : 'low';

    return (
        <div className="hitl-overlay">
            <div className="hitl-modal">
                {/* Header */}
                <div className="hitl-header">
                    <span className="hitl-header-icon">⚠️</span>
                    <div className="hitl-header-text">
                        <h3>APPROVAL REQUIRED</h3>
                        <span className="hitl-timer">
                            Auto-blocking in {timeLeft}s
                        </span>
                    </div>
                </div>

                <div className="hitl-body">
                    {/* URL */}
                    <div className="hitl-url-card">
                        <span>🔗</span>
                        <span className="url-text">{url}</span>
                    </div>

                    {/* Risk Score */}
                    <div className="hitl-risk-display">
                        <span className={`hitl-risk-score ${riskLevel}`}>
                            {Math.round(overallRisk)}
                        </span>
                        <div className="hitl-risk-bar-container">
                            <div className="hitl-risk-bar">
                                <div
                                    className={`hitl-risk-bar-fill ${riskLevel}`}
                                    style={{ width: `${overallRisk}%` }}
                                />
                            </div>
                            <span className="hitl-risk-label">Risk Score / 100</span>
                        </div>
                    </div>

                    {/* LLM Verdict */}
                    {llmVerdict && (
                        <div className="hitl-llm-card">
                            <h4>Guard LLM Says</h4>
                            <p>"{llmVerdict.explanation}"</p>
                        </div>
                    )}

                    {/* Threats */}
                    {threats && threats.length > 0 && (
                        <div className="hitl-threats-list">
                            {threats.slice(0, 4).map((t, idx) => (
                                <div className="hitl-threat-item" key={idx}>
                                    <span className={`hitl-threat-severity ${(t.severity || 'high').toLowerCase()}`}>
                                        {(t.severity || 'HIGH').toUpperCase()}
                                    </span>
                                    <span>{t.type} — {t.description?.slice(0, 80)}</span>
                                </div>
                            ))}
                        </div>
                    )}

                    {/* Risk Breakdown */}
                    {policyDecision && (
                        <div className="hitl-breakdown-row">
                            <div className="hitl-breakdown-item">
                                <div className="breakdown-value">{Math.round(policyDecision.dom_score)}</div>
                                <div className="breakdown-label">DOM</div>
                            </div>
                            <div className="hitl-breakdown-item">
                                <div className="breakdown-value">{Math.round(policyDecision.llm_score)}</div>
                                <div className="breakdown-label">LLM</div>
                            </div>
                            <div className="hitl-breakdown-item">
                                <div className="breakdown-value">{Math.round(policyDecision.heuristic_score)}</div>
                                <div className="breakdown-label">Heuristic</div>
                            </div>
                        </div>
                    )}
                </div>

                {/* Action Buttons */}
                <div className="hitl-actions">
                    <button className="hitl-btn hitl-btn-approve" onClick={handleApprove}>
                        ✅ Approve
                    </button>
                    <button className="hitl-btn hitl-btn-block" onClick={handleBlock}>
                        ❌ Block & Skip
                    </button>
                </div>
            </div>
        </div>
    );
};

export default HITLApproval;
