from typing import Annotated

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Body, Header
import jwt


class DreamServer(FastAPI):

    JWT_SECRET = "fear_is_the_mind_killer"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.users: dict[str, dict[str, str | dict]] = {}
        self.open_websockets: dict[tuple[str, str], WebSocket] = {}


app = DreamServer()

@app.post("/register", status_code=201)
async def register(
    username: Annotated[str, Body()],
    identity: Annotated[str, Body()]
):
    # Check if username is already registered
    if username in app.users:
        raise Exception("User already registered")

    # Add the new user to the users dictionary
    app.users[username] = {
        "identity": identity,
        "pending_messages": {}
    }

    # Return an authentication token for the newly registered user
    return jwt.encode({"username": username}, app.JWT_SECRET, algorithm="HS256")

@app.get("/{recipient}/id")
async def get_recipient_id(recipient: str):
    return app.users[recipient]["identity"]

@app.websocket("/{recipient}/chat")
async def chat_endpoint(
    recipient: str,
    token: Annotated[str, Header()],
    websocket: WebSocket
):    
    # Get the sender's username from the token
    token = jwt.decode(token, app.JWT_SECRET, algorithms=["HS256"])
    sender = token["username"]

    # Close existing WebSocket connection if it exists
    if (sender, recipient) in app.open_websockets:
        await app.open_websockets[(sender, recipient)].close()
        del app.open_websockets[(sender, recipient)]
    
    # Accept the new WebSocket and store it
    await websocket.accept()
    app.open_websockets[(sender, recipient)] = websocket

    # Flush any pending messages for the sender
    pending = app.users[sender]["pending_messages"].setdefault(recipient, [])
    for message in pending:
        await websocket.send_json(message)
    app.users[sender]["pending_messages"][recipient] = []

    try:
        while True:
            # Listen for incoming messages from the sender
            data = await websocket.receive_json()
            print(f"Received message from {sender} to {recipient}: {data}")

            # Forward the message to the recipient if they are connected,
            # otherwise store it as a pending message
            if (recipient, sender) in app.open_websockets:
                await app.open_websockets[(recipient, sender)].send_json(data)
            else:
                app.users[recipient]["pending_messages"].setdefault(sender, []).append(data)
    except WebSocketDisconnect:
        if (sender, recipient) in app.open_websockets:
            del app.open_websockets[(sender, recipient)]
