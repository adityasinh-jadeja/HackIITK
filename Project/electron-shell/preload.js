/**
 * Secure Agentic Browser — Preload Script
 *
 * Bridges the renderer process to the main process using contextBridge.
 * Only exposes a minimal, well-defined API surface — no raw IPC,
 * no Node.js globals, no file system access.
 *
 * Security:
 *  - contextIsolation: true (renderer cannot access this scope)
 *  - nodeIntegration: false
 *  - Only whitelisted methods are exposed
 */

"use strict";

const { contextBridge, ipcRenderer } = require("electron");

// ---------------------------------------------------------------------------
// Whitelisted channels for renderer → main communication
// ---------------------------------------------------------------------------

const SEND_CHANNELS = [
  "send-goal",
  "hitl-respond",
  "navigate-to",
  "get-page-info",
  "stop-agent",
  "set-browser-bounds",
];

const RECEIVE_CHANNELS = [
  "backend-message",
  "backend-status",
  "page-navigated",
  "page-title-updated",
];

// ---------------------------------------------------------------------------
// Expose safe API to renderer (window.electronAPI)
// ---------------------------------------------------------------------------

contextBridge.exposeInMainWorld("electronAPI", {
  /**
   * Send a natural-language goal to the agent backend.
   * @param {string} goal
   * @returns {Promise<boolean>} true if sent successfully
   */
  sendGoal: (goal) => ipcRenderer.invoke("send-goal", goal),

  /**
   * Respond to a Human-in-the-Loop request.
   * @param {string} requestId
   * @param {boolean} approved
   * @returns {Promise<boolean>}
   */
  hitlRespond: (requestId, approved) =>
    ipcRenderer.invoke("hitl-respond", { requestId, approved }),

  /**
   * Navigate the BrowserView to a URL.
   * @param {string} url
   * @returns {Promise<boolean>}
   */
  navigateTo: (url) => ipcRenderer.invoke("navigate-to", url),

  /**
   * Get info about the currently loaded page.
   * @returns {Promise<{url: string, title: string} | null>}
   */
  getPageInfo: () => ipcRenderer.invoke("get-page-info"),

  /**
   * Stop the running agent.
   * @returns {Promise<boolean>}
   */
  stopAgent: () => ipcRenderer.invoke("stop-agent"),

  /**
   * Update BrowserView bounds (e.g., when toggling sidebar).
   * @param {{x: number, y: number, width: number, height: number}} bounds
   * @returns {Promise<void>}
   */
  setBrowserBounds: (bounds) => ipcRenderer.invoke("set-browser-bounds", bounds),

  // --- Event listeners (main → renderer) ---

  /**
   * Listen for messages from the Python backend.
   * @param {function} callback - receives the parsed message object
   * @returns {function} unsubscribe function
   */
  onBackendMessage: (callback) => {
    const handler = (_event, message) => callback(message);
    ipcRenderer.on("backend-message", handler);
    return () => ipcRenderer.removeListener("backend-message", handler);
  },

  /**
   * Listen for backend connection status changes.
   * @param {function} callback - receives { connected: boolean }
   * @returns {function} unsubscribe function
   */
  onBackendStatus: (callback) => {
    const handler = (_event, status) => callback(status);
    ipcRenderer.on("backend-status", handler);
    return () => ipcRenderer.removeListener("backend-status", handler);
  },

  /**
   * Listen for page navigation events from BrowserView.
   * @param {function} callback - receives { url: string }
   * @returns {function} unsubscribe function
   */
  onPageNavigated: (callback) => {
    const handler = (_event, data) => callback(data);
    ipcRenderer.on("page-navigated", handler);
    return () => ipcRenderer.removeListener("page-navigated", handler);
  },

  /**
   * Listen for page title updates from BrowserView.
   * @param {function} callback - receives { title: string }
   * @returns {function} unsubscribe function
   */
  onPageTitleUpdated: (callback) => {
    const handler = (_event, data) => callback(data);
    ipcRenderer.on("page-title-updated", handler);
    return () => ipcRenderer.removeListener("page-title-updated", handler);
  },
});
