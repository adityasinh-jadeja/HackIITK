import sys
import asyncio
import uvicorn

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

if __name__ == "__main__":
    # Setting loop="none" tells Uvicorn NOT to aggressively overwrite
    # the WindowsProactorEventLoopPolicy back to SelectorEventLoop
    # reload=False to avoid Python 3.14 Windows ProactorEventLoop socket bug
    # (OSError: [WinError 87] The parameter is incorrect)
    # Restart manually after code changes: Ctrl+C then python run_server.py
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=False, loop="none")
