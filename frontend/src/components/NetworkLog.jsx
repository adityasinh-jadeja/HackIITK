import React, { useState, useMemo } from 'react';
import './NetworkLog.css';

/**
 * NetworkLog — Real-time network activity panel for the security dashboard.
 * Shows all network requests made from the sandboxed browser context.
 * Color-coded: green (allowed), red (blocked).
 * Filterable by method and action.
 */
const NetworkLog = ({ networkLog = [], networkStats = {} }) => {
    const [filter, setFilter] = useState('all'); // all | blocked | post
    const [expandedIdx, setExpandedIdx] = useState(null);

    const filteredLog = useMemo(() => {
        if (!networkLog || networkLog.length === 0) return [];
        let filtered = [...networkLog];
        if (filter === 'blocked') {
            filtered = filtered.filter(e => e.action === 'BLOCK');
        } else if (filter === 'post') {
            filtered = filtered.filter(e => e.method === 'POST');
        }
        // Show newest first
        return filtered.reverse();
    }, [networkLog, filter]);

    const stats = networkStats || {};
    const totalRequests = stats.total_requests || networkLog.length;
    const blocked = stats.blocked || 0;
    const allowed = stats.allowed || (totalRequests - blocked);
    const blockRate = stats.block_rate || 0;

    const formatTimestamp = (ts) => {
        if (!ts) return '';
        try {
            const d = new Date(ts);
            return d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
        } catch {
            return '';
        }
    };

    const truncateUrl = (url, maxLen = 60) => {
        if (!url) return '';
        // Remove protocol for display
        const clean = url.replace(/^https?:\/\//, '');
        return clean.length > maxLen ? clean.substring(0, maxLen) + '…' : clean;
    };

    if (!networkLog || networkLog.length === 0) {
        return (
            <div className="network-log-container">
                <div className="network-empty">
                    <div className="network-empty-icon">🌐</div>
                    <h3>No Network Activity</h3>
                    <p>Network requests will appear here when a sandboxed page is evaluated.</p>
                    <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                        Click "Scan" on any URL to start a sandboxed evaluation with full network monitoring.
                    </p>
                </div>
            </div>
        );
    }

    return (
        <div className="network-log-container">
            {/* Stats Bar */}
            <div className="network-stats-bar">
                <div className="net-stat">
                    <span className="net-stat-value text-white">{totalRequests}</span>
                    <span className="net-stat-label">Total</span>
                </div>
                <div className="net-stat">
                    <span className="net-stat-value green-text">{allowed}</span>
                    <span className="net-stat-label">Allowed</span>
                </div>
                <div className="net-stat">
                    <span className="net-stat-value red-text">{blocked}</span>
                    <span className="net-stat-label">Blocked</span>
                </div>
                <div className="net-stat">
                    <span className={`block-rate-badge ${blockRate > 20 ? 'danger' : blockRate > 5 ? 'warning' : 'safe'}`}>
                        {blockRate}%
                    </span>
                    <span className="net-stat-label">Block Rate</span>
                </div>
            </div>

            {/* Filter Bar */}
            <div className="network-filters">
                <span className="net-live-dot"></span>
                <button
                    className={`net-filter-btn ${filter === 'all' ? 'active' : ''}`}
                    onClick={() => setFilter('all')}
                >
                    All ({networkLog.length})
                </button>
                <button
                    className={`net-filter-btn ${filter === 'blocked' ? 'active' : ''}`}
                    onClick={() => setFilter('blocked')}
                >
                    ❌ Blocked ({blocked})
                </button>
                <button
                    className={`net-filter-btn ${filter === 'post' ? 'active' : ''}`}
                    onClick={() => setFilter('post')}
                >
                    POST Only
                </button>
            </div>

            {/* Request List */}
            <div className="network-request-list">
                {filteredLog.map((entry, idx) => {
                    const isBlocked = entry.action === 'BLOCK';
                    const isExpanded = expandedIdx === idx;

                    return (
                        <React.Fragment key={idx}>
                            <div
                                className={`net-request-row ${isBlocked ? 'blocked' : 'allowed'}`}
                                onClick={() => setExpandedIdx(isExpanded ? null : idx)}
                            >
                                <span className="net-action-icon">
                                    {isBlocked ? '❌' : '✅'}
                                </span>
                                <span className={`net-method-badge ${entry.method?.toLowerCase()}`}>
                                    {entry.method}
                                </span>
                                <span className={`net-url ${isBlocked ? 'blocked-url' : ''}`}
                                      title={entry.url}>
                                    {truncateUrl(entry.url)}
                                </span>
                                <span className="net-resource-type">
                                    {entry.resource_type}
                                </span>
                                <span className="net-timestamp">
                                    {formatTimestamp(entry.timestamp)}
                                </span>
                            </div>
                            {isExpanded && isBlocked && entry.reason && (
                                <div className="net-block-reason">
                                    🛡️ <strong>Blocked:</strong> {entry.reason}
                                </div>
                            )}
                        </React.Fragment>
                    );
                })}

                {filteredLog.length === 0 && (
                    <div className="network-empty" style={{ padding: '2rem' }}>
                        <p>No requests match the current filter.</p>
                    </div>
                )}
            </div>
        </div>
    );
};

export default NetworkLog;
