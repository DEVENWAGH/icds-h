import asyncio


class ConnectionManager:
    """Tracks active /ws/live WebSocket clients and fans out JSON events."""

    def __init__(self):
        self.connections = []

    async def connect(self, websocket):
        await websocket.accept()
        self.connections.append(websocket)

    def disconnect(self, websocket):
        if websocket in self.connections:
            self.connections.remove(websocket)

    async def broadcast(self, data: dict):
        dead_connections = []

        for websocket in list(self.connections):
            try:
                await websocket.send_json(data)
            except Exception:
                dead_connections.append(websocket)

        for websocket in dead_connections:
            if websocket in self.connections:
                self.connections.remove(websocket)


manager = ConnectionManager()

# Reference to the main asyncio event loop, captured at app startup.
# Needed so synchronous request handlers (which FastAPI runs in a threadpool)
# can push events onto the same loop that owns the WebSocket connections.
_main_loop = None


def set_main_loop(loop):
    global _main_loop
    _main_loop = loop


def broadcast_threadsafe(data: dict):
    """Schedule a WebSocket broadcast from a synchronous / threadpool context.

    Used by REST endpoints (e.g. the Attack Simulator) so a manually launched
    attack is pushed into the Live Threat Feed in real time, exactly like the
    automatic dataset-replay pipeline does.
    """
    if _main_loop is None:
        return
    try:
        asyncio.run_coroutine_threadsafe(manager.broadcast(data), _main_loop)
    except Exception as error:
        print(f"[WS] broadcast_threadsafe failed: {error}")
