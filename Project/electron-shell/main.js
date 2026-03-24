/**
 * Secure Agentic Browser — Electron Main Process
 *
 * Responsibilities:
 *  1. Create the main BrowserWindow with a BrowserView for web content.
 *  2. Launch Chromium with --remote-debugging-port so Playwright (Python)
 *     can connect via CDP.
 *  3. Spawn the Python backend as a child process.
 *  4. Relay IPC messages between the renderer (overlay UI) and the Python
 *     backend WebSocket server.
 *
 * Security:
 *  - nodeIntegration OFF in all renderers
 *  - contextIsolation ON
 *  - webSecurity ON
 *  - Strict preload via contextBridge
 */

"use strict";

const { app, BrowserWindow, BrowserView, ipcMain, session } = require("electron");
const path = require("path");
const { spawn } = require("child_process");
const WebSocket = require("ws");

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const CDP_PORT = 9222;
const IPC_WS_PORT = 8765;
const PYTHON_API_PORT = 8000;
const IS_DEV = process.argv.includes("--dev");

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

let mainWindow = null;
let browserView = null;
let pythonProcess = null;
let wsConnection = null;
let wsReconnectTimer = null;

// ---------------------------------------------------------------------------
// Python backend lifecycle
// ---------------------------------------------------------------------------

function spawnPythonBackend() {
  const pythonCmd = process.platform === "win32" ? "python" : "python3";
  const projectDir = path.resolve(__dirname, "..");

  pythonProcess = spawn(
    pythonCmd,
    ["-m", "uvicorn", "api.main:app", "--host", "127.0.0.1", "--port", String(PYTHON_API_PORT)],
    {
      cwd: projectDir,
      env: {
        ...process.env,
        SAB_CDP_ENDPOINT: `http://127.0.0.1:${CDP_PORT}`,
        PYTHONUNBUFFERED: "1",
      },
      stdio: ["pipe", "pipe", "pipe"],
    }
  );

  pythonProcess.stdout.on("data", (data) => {
    const msg = data.toString().trim();
    if (msg) console.log(`[python] ${msg}`);
  });

  pythonProcess.stderr.on("data", (data) => {
    const msg = data.toString().trim();
    if (msg) console.error(`[python:err] ${msg}`);
  });

  pythonProcess.on("exit", (code) => {
    console.log(`[python] Process exited with code ${code}`);
    pythonProcess = null;
  });

  pythonProcess.on("error", (err) => {
    console.error(`[python] Failed to start: ${err.message}`);
    pythonProcess = null;
  });

  console.log(`[main] Python backend started (PID: ${pythonProcess.pid})`);
}

// ---------------------------------------------------------------------------
// WebSocket IPC to Python backend
// ---------------------------------------------------------------------------

function connectToBackendWS() {
  if (wsConnection && wsConnection.readyState === WebSocket.OPEN) return;

  const url = `ws://127.0.0.1:${IPC_WS_PORT}`;
  console.log(`[ipc] Connecting to Python backend at ${url}...`);

  wsConnection = new WebSocket(url);

  wsConnection.on("open", () => {
    console.log("[ipc] Connected to Python backend WebSocket.");
    if (wsReconnectTimer) {
      clearInterval(wsReconnectTimer);
      wsReconnectTimer = null;
    }
    // Notify renderer
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send("backend-status", { connected: true });
    }
  });

  wsConnection.on("message", (data) => {
    try {
      const message = JSON.parse(data.toString());
      // Forward all backend messages to renderer
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send("backend-message", message);
      }

      // Handle navigation commands from the agent
      if (message.type === "navigate" && browserView) {
        browserView.webContents.loadURL(message.payload.url).catch((err) => {
          console.error(`[main] Navigation failed: ${err.message}`);
        });
      }
    } catch (err) {
      console.error(`[ipc] Failed to parse message: ${err.message}`);
    }
  });

  wsConnection.on("close", () => {
    console.log("[ipc] WebSocket disconnected. Reconnecting in 2s...");
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send("backend-status", { connected: false });
    }
    scheduleReconnect();
  });

  wsConnection.on("error", (err) => {
    // Suppress ECONNREFUSED during startup — backend isn't ready yet
    if (err.code !== "ECONNREFUSED") {
      console.error(`[ipc] WebSocket error: ${err.message}`);
    }
    scheduleReconnect();
  });
}

function scheduleReconnect() {
  if (wsReconnectTimer) return;
  wsReconnectTimer = setInterval(() => {
    connectToBackendWS();
  }, 2000);
}

function sendToBackend(message) {
  if (wsConnection && wsConnection.readyState === WebSocket.OPEN) {
    wsConnection.send(JSON.stringify(message));
    return true;
  }
  console.warn("[ipc] Cannot send — WebSocket not connected.");
  return false;
}

// ---------------------------------------------------------------------------
// IPC handlers (renderer → main → backend)
// ---------------------------------------------------------------------------

function setupIPCHandlers() {
  // Renderer sends a user goal
  ipcMain.handle("send-goal", async (_event, goal) => {
    return sendToBackend({ type: "goal", payload: goal });
  });

  // Renderer sends a HitL decision
  ipcMain.handle("hitl-respond", async (_event, { requestId, approved }) => {
    return sendToBackend({
      type: "hitl_response",
      payload: { request_id: requestId, approved },
    });
  });

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

  // Manual stop of agent
  ipcMain.handle("stop-agent", async () => {
    return sendToBackend({ type: "stop", payload: {} });
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
    icon: path.join(__dirname, "renderer", "assets", "icon.png"),
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
      webSecurity: true,
    },
    // Frameless for custom titlebar feel (optional — set to false to keep OS frame)
    frame: true,
    show: false,
  });

  // Load the renderer UI
  mainWindow.loadFile(path.join(__dirname, "renderer", "index.html"));

  // --- BrowserView for web content ---
  browserView = new BrowserView({
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
      webSecurity: true,
      // Do NOT use a preload for the browsed page — it's untrusted content
    },
  });

  mainWindow.setBrowserView(browserView);

  // Position the BrowserView (adjusted once renderer tells us the layout)
  // Default: below command bar (60px), with sidebar (350px)
  const COMMAND_BAR_HEIGHT = 60;
  const SIDEBAR_WIDTH = 380;
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

  // Navigate to a welcome/blank page
  browserView.webContents.loadURL("about:blank");

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
    if (!browserView || mainWindow.isDestroyed()) return;
    const newBounds = mainWindow.getContentBounds();
    browserView.setBounds({
      x: 0,
      y: COMMAND_BAR_HEIGHT,
      width: newBounds.width - SIDEBAR_WIDTH,
      height: newBounds.height - COMMAND_BAR_HEIGHT,
    });
  });

  // IPC: Renderer can request BrowserView bounds update (e.g., toggle sidebar)
  ipcMain.handle("set-browser-bounds", async (_event, { x, y, width, height }) => {
    if (!browserView) return;
    browserView.setBounds({ x, y, width, height });
  });

  // Show once ready
  mainWindow.once("ready-to-show", () => {
    mainWindow.show();
    if (IS_DEV) {
      mainWindow.webContents.openDevTools({ mode: "detach" });
    }
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

  // Spawn Python backend
  spawnPythonBackend();

  // Connect to the backend WebSocket (with retry)
  // Give Python a few seconds to start up
  setTimeout(() => {
    connectToBackendWS();
  }, 3000);
});

app.on("window-all-closed", () => {
  // Kill Python backend
  if (pythonProcess) {
    console.log("[main] Killing Python backend...");
    pythonProcess.kill();
    pythonProcess = null;
  }

  // Close WebSocket
  if (wsConnection) {
    wsConnection.close();
    wsConnection = null;
  }

  if (wsReconnectTimer) {
    clearInterval(wsReconnectTimer);
    wsReconnectTimer = null;
  }

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
