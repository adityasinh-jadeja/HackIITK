/**
 * Secure Agentic Browser — Electron Main Process
 *
 * Responsibilities:
 *  1. Create the main BrowserWindow with a BrowserView for web content.
 *  2. Relay IPC messages between the React renderer (overlay UI) and Node Backend.
 *
 * Security:
 *  - nodeIntegration OFF in all renderers
 *  - contextIsolation ON
 *  - webSecurity ON
 *  - Strict preload via contextBridge
 */

"use strict";

const { app, BrowserWindow, BrowserView, ipcMain } = require("electron");
const path = require("path");

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const IS_DEV = process.env.NODE_ENV === "development" || process.argv.includes("--dev");

// Enable CDP so Playwright can attach from the Node.js backend
app.commandLine.appendSwitch('remote-debugging-port', '9222');

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

let mainWindow = null;
let browserView = null;

// ---------------------------------------------------------------------------
// IPC handlers (renderer → main)
// ---------------------------------------------------------------------------

function setupIPCHandlers() {
  // Renderer requests navigation
  ipcMain.handle("navigate-to", async (_event, url) => {
    if (!browserView) return false;
    try {
      // Validate URL
      const parsed = new URL(url);
      if (!["http:", "https:"].includes(parsed.protocol)) {
        console.warn(`[main] Blocked navigation to non-HTTP URL: ${url}`);
        return false;
      }
      await browserView.webContents.loadURL(url);
      return true;
    } catch (err) {
      console.error(`[main] Navigation error: ${err.message}`);
      return false;
    }
  });

  // Get current page info
  ipcMain.handle("get-page-info", async () => {
    if (!browserView) return null;
    return {
      url: browserView.webContents.getURL(),
      title: browserView.webContents.getTitle(),
    };
  });

  // Toggle dashboard mode (hides/shows browserView)
  ipcMain.handle("toggle-dashboard", async (_event, isOpen) => {
    if (!mainWindow) return;
    mainWindow.isDashboardOpen = isOpen;
    
    if (isOpen) {
      if (browserView) {
        mainWindow.removeBrowserView(browserView);
      }
    } else {
      if (browserView) {
        mainWindow.setBrowserView(browserView);
        // Force a resize to reset bounds
        const bounds = mainWindow.getContentBounds();
        const COMMAND_BAR_HEIGHT = 60;
        // Sidebar isn't fully set up yet in react, but we'll reserve it if needed
        const SIDEBAR_WIDTH = 0; 
        browserView.setBounds({
          x: 0,
          y: COMMAND_BAR_HEIGHT,
          width: bounds.width - SIDEBAR_WIDTH,
          height: bounds.height - COMMAND_BAR_HEIGHT,
        });
      }
    }
  });

// Renderer sends a user goal (mock for now, should connect to Node backend)
  ipcMain.handle("send-goal", async (_event, goal) => {
    console.log("[main] Received goal:", goal);
    try {
        await fetch('http://localhost:5000/api/agent/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ goal })
        });
    } catch (err) {
        console.error("Backend offline?");
    }
    return true;
});

  // Manual stop of agent
  ipcMain.handle("stop-agent", async () => {
    console.log("[main] Stop agent requested");
    return true;
  });

  ipcMain.handle("hitl-respond", async (_event, { requestId, approved }) => {
    console.log("[main] HITL respond:", requestId, approved);
    return true;
  });
}

// ---------------------------------------------------------------------------
// Window creation
// ---------------------------------------------------------------------------

function createMainWindow() {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 900,
    minHeight: 600,
    title: "Secure Agentic Browser",
    backgroundColor: "#0a0a0f",
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
      webSecurity: true,
    },
    frame: true,
    show: false,
  });

  // Load the React renderer UI
  if (IS_DEV || true) { // Forcing true for local dev without NODE_ENV explicitly set
    mainWindow.loadURL('http://localhost:5173');
  } else {
    // In production, load the built React app
    mainWindow.loadFile(path.join(__dirname, '../frontend-react/dist/index.html'));
  }

  // --- BrowserView for web content ---
  browserView = new BrowserView({
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
      webSecurity: true,
    },
  });

  mainWindow.setBrowserView(browserView);

  // Position the BrowserView
  const COMMAND_BAR_HEIGHT = 60;
  const SIDEBAR_WIDTH = 0;
  const bounds = mainWindow.getContentBounds();
  browserView.setBounds({
    x: 0,
    y: COMMAND_BAR_HEIGHT,
    width: bounds.width - SIDEBAR_WIDTH,
    height: bounds.height - COMMAND_BAR_HEIGHT,
  });
  browserView.setAutoResize({
    width: true,
    height: true,
    horizontal: false,
    vertical: false,
  });

  // Navigate to a welcome/blank page initially
  browserView.webContents.loadURL("https://example.com");

  // Forward BrowserView navigation events to renderer
  browserView.webContents.on("did-navigate", (_event, url) => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send("page-navigated", { url });
    }
  });

  browserView.webContents.on("did-navigate-in-page", (_event, url) => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send("page-navigated", { url });
    }
  });

  browserView.webContents.on("page-title-updated", (_event, title) => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send("page-title-updated", { title });
    }
  });

  // Handle window resize to keep BrowserView proportional
  mainWindow.on("resize", () => {
    if (!browserView || mainWindow.isDestroyed() || mainWindow.isDashboardOpen) return;
    const newBounds = mainWindow.getContentBounds();
    browserView.setBounds({
      x: 0,
      y: COMMAND_BAR_HEIGHT,
      width: newBounds.width - SIDEBAR_WIDTH,
      height: newBounds.height - COMMAND_BAR_HEIGHT,
    });
  });

  // IPC: Renderer can request BrowserView bounds update
  ipcMain.handle("set-browser-bounds", async (_event, { x, y, width, height }) => {
    if (!browserView) return;
    browserView.setBounds({ x, y, width, height });
  });

  // Show once ready
  mainWindow.once("ready-to-show", () => {
    mainWindow.show();
    // mainWindow.webContents.openDevTools({ mode: "detach" });
  });

  mainWindow.on("closed", () => {
    mainWindow = null;
    browserView = null;
  });
}

// ---------------------------------------------------------------------------
// App lifecycle
// ---------------------------------------------------------------------------

app.whenReady().then(() => {
  createMainWindow();
  setupIPCHandlers();
});

app.on("window-all-closed", () => {
  app.quit();
});

app.on("activate", () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createMainWindow();
  }
});

// Prevent new window creation from browsed pages
app.on("web-contents-created", (_event, contents) => {
  contents.setWindowOpenHandler(() => {
    return { action: "deny" };
  });
});
