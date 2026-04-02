---
description: How to start and stop the backend and frontend servers
---

## Kill All Running Processes
```powershell
taskkill /F /IM python.exe 2>$null; taskkill /F /IM node.exe 2>$null; echo "All stopped"
```

## Start Backend (Terminal 1)
```powershell
cd d:\Hackathon\Secure_browser\ABS_HACKIITK\backend-python
$env:PYTHONIOENCODING="utf-8"; .\venv\Scripts\python.exe -m uvicorn app.main:app --port 8000 --reload
```

## Start Frontend (Terminal 2)
```powershell
cd d:\Hackathon\Secure_browser\ABS_HACKIITK\frontend
npm run dev
```

## Open in Browser
```
http://localhost:5173
```
