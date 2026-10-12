from fastapi import FastAPI, WebSocket
from pydantic import BaseModel

app = FastAPI()



@app.websocket("/ws")
async def endpoint(websocket: WebSocket):
    ...
