# 🎓 College GPU (Ollama) Setup Guide

This guide contains the exact step-by-step instructions to switch your Secure Agentic Browser from using the Cloud API (Gemini) on your laptop to using the 20GB NVIDIA GPU at your college.

---

## 🛑 Step 1: Install & Set Up Ollama on the College PC

When you get to the college PC with the 20GB GPU, your first step is to install Ollama and download the LLM model.

1. **Download Ollama:** Go to [ollama.com/download](https://ollama.com/download) on the college PC and install the Windows/Linux version.
2. **Pull the Model:** Open a terminal on the college PC and run:
   ```powershell
   ollama run llama3
   ```
   *(Note: This defaults to the 8B parameter model, which fits beautifully in 20GB VRAM and is very fast! It will take a few minutes to download the ~4.7GB model weights).*
3. **Keep it Running:** Once the model downloads, you will see a `>>>` prompt. You can type `/bye` to exit the chat, but **the Ollama background server is now running on port `11434`** on that PC.

---

## 🌐 Step 2: Connect Your Laptop to the College PC

Your laptop (running the frontend/backend) needs to talk to the college PC (running the AI). 

### Option A: Using Local College WiFi (Fastest & Simplest)
If both your laptop and the college PC are connected to the exact same college WiFi network:
1. On the **College PC**, open command prompt and type `ipconfig` (Windows) or `ifconfig` (Mac/Linux). Look for the IPv4 Address (e.g., `192.168.1.55`).
2. By default, Ollama only listens to `localhost`. You must tell it to listen to the network. On the College PC, set an environment variable before starting Ollama:
   ```powershell
   # On Windows (College PC):
   set OLLAMA_HOST=0.0.0.0
   ollama serve
   ```
3. On your **Laptop**, open your `backend-python/.env` file and update it:
   ```ini
   LLM_PROVIDER=ollama
   OLLAMA_BASE_URL=http://192.168.1.55:11434  # Replace with the College PC's IP
   OLLAMA_MODEL=llama3
   ```

### Option B: Using Ngrok (Best for Hackathon Pitching / Different Networks)
If your laptop and the college PC cannot see each other on the network, use Ngrok to create a secure, public tunnel to the GPU.
1. On the **College PC**, install Ngrok, then run:
   ```powershell
   ngrok http 11434
   ```
2. Ngrok will output a public URL (e.g., `https://a1b2c3d4.ngrok-free.app`).
3. On your **Laptop**, update your `backend-python/.env` file:
   ```ini
   LLM_PROVIDER=ollama
   OLLAMA_BASE_URL=https://a1b2c3d4.ngrok-free.app
   OLLAMA_MODEL=llama3
   ```

---

## 🧪 Step 3: Test the Connection!

Now that the `.env` on your laptop is pointing to your college GPU, start your backend server on your laptop as usual:

```powershell
cd backend-python
.\venv\Scripts\Activate
python -m uvicorn app.main:app --port 8000 --reload
```

Open a **new terminal** on your laptop and run this explicit testing command to trigger an evaluation on a test page:

```powershell
Invoke-WebRequest -UseBasicParsing -Uri "http://localhost:8000/api/evaluate" -Method POST -ContentType "application/json" -Body '{"url": "file:///D:/Hackathon/Secure_browser/ABS_HACKIITK/backend-python/tests/test_pages/phishing_login.html", "goal": "Log into my account safely"}' | Select-Object -ExpandProperty Content | ConvertFrom-Json | ConvertTo-Json -Depth 5
```

---

## 🎯 Expected Output & Proof it Works

When you run that test command, you should see the backend wait for 1-3 seconds while your College GPU spins up and analyzes the DOM. You will receive a JSON response that looks like this:

```json
{
    "threats": [
        {
            "type": "deceptive_form",
            "severity": "high",
            "description": "Found a hidden JWT token form field."
        }
    ],
    "llm_verdict": {
        "classification": "malicious",
        "explanation": "The page contains a deceptive login form asking for sensitive credentials on a non-standard domain.",
        "confidence": 0.95,
        "goal_alignment": 0.1,
        "recommended_action": "block"
    },
    "policy_decision": {
        "action": "BLOCK",
        "aggregate_risk": 98.5,
        "dom_score": 100.0,
        "llm_score": 95.0,
        "heuristic_score": 15.0,
        "reason": "Aggregate risk: DOM=100, LLM=95, Heuristic=15. Guard LLM: malicious (The page contains...)",
        "requires_hitl": false
    },
    "latency_ms": 2304.5
}
```

### How to Prove the Resilience Architecure works to the Judges:
1. **The Cache Test:** Run that exact same `Invoke-WebRequest` command a second time. Look at the `latency_ms` field at the very bottom. The first time it might be `2304.5` (2.3 seconds) while the GPU thought about it. The second time, because of our MongoDB cache, it will be `1.5` (0.001 seconds), and you won't see the GPU spike. This proves your smart-caching layer works!
2. **The Degradation Test:** Disconnect from the internet (or turn off the College PC). Run the test command on the *benign* shopping HTML page. The `latency_ms` will jump to 10-15 seconds while `tenacity` retries the connection 3 times. But instead of crashing, it will return `"action": "ALLOW"` with the explanation `"LLM unavailable. Auto-allowed based on perfectly clean DOM scan."` This proves your system degrades gracefully without breaking the browser for safe pages!
