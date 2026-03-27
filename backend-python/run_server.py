import sys
import asyncio
import uvicorn

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

if __name__ == "__main__":
    # Setting loop="none" tells Uvicorn NOT to aggressively overwrite
    # the WindowsProactorEventLoopPolicy back to SelectorEventLoop
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True, loop="none")
