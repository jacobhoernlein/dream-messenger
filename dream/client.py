from argparse import ArgumentParser
from dataclasses import dataclass
from datetime import datetime

from rich.align import Align
from rich.panel import Panel
from rich.text import Text
from textual import events, work
from textual.app import App, ComposeResult
from textual.widgets import (
    Header, 
    RichLog,
    TextArea,
)
import websockets


class ChatInput(TextArea):

    def _on_key(self, event: events.Key) -> None:
        if event.key == "enter":
            self.post_message(self.Submitted(self, self.text))
            event.prevent_default()
            return

        super()._on_key(event)

    class Submitted(events.Message):
        def __init__(self, text_area: "ChatInput", value: str) -> None:
            self.text_area = text_area
            self.value = value
            super().__init__()


@dataclass
class ChatEntry:
    message: str
    timestamp: str
    sent: bool


class DreamClient(App):

    MIN_INPUT_HEIGHT = 3
    MAX_INPUT_HEIGHT = 8

    CSS_PATH = "client.tcss"
    TITLE = "Dream Client"

    def __init__(self, host: str, port: int, username: str) -> None:
        super().__init__()
        self.__host = host
        self.__port = port
        self.__recipient = username
        self.__chat_entries: list[ChatEntry] = []
        self.__ws: websockets.ClientConnection | None = None

    def compose(self) -> ComposeResult:
        yield Header(icon="💭")
        yield RichLog(auto_scroll=True, wrap=True, min_width=24)
        yield ChatInput(placeholder=f"Message {self.__recipient}...", id="message-box")
        self.sub_title = f"Chat with {self.__recipient}"

    def on_mount(self) -> None:
        """Handles the mounting of the app, setting up initial focus and resizing the message box."""
        
        self.__resize_message_box()
        self.query_one(ChatInput).focus()
        self.open_websocket()

    @work(exclusive=True)
    async def open_websocket(self) -> None:
        """Opens a websocket connection to the server and listens for incoming messages."""

        try:
            async with websockets.connect(f"ws://{self.__host}:{self.__port}/ws") as ws:
                self.__ws = ws
                async for message in ws:
                    self.__chat_entries.append(
                        ChatEntry(
                            message=message,
                            sent=False,
                            timestamp=datetime.now().strftime("[%H:%M:%S]")
                        )
                    )
                    self.__write_entry(self.__chat_entries[-1])
        except websockets.ConnectionClosed:
            self.notify("Connection closed.")
        finally:
            self.__ws = None

    def on_text_area_changed(self, _: TextArea.Changed) -> None:
        """Handles changes to the text area, such as when the user types a message."""
        
        self.__resize_message_box()

    def on_resize(self, _: events.Resize) -> None:
        """Handles the resizing of the chat log and message box when 
        the app window is resized.
        """

        self.__resize_message_box()
        if self.is_mounted:
            self.query_one(RichLog).clear()
            for entry in self.__chat_entries:
                self.__write_entry(entry)

    async def on_chat_input_submitted(self, event: ChatInput.Submitted) -> None:
        """Handles the submission of a chat message from the input box."""
        
        # Strip the message of leading and trailing whitespace
        message = event.value.strip()
        if not message:
            return

        # Create a new chat entry with the current timestamp
        self.__chat_entries.append(
            ChatEntry(
                message=message,
                sent=True,
                timestamp=datetime.now().strftime("[%H:%M:%S]")
            )
        )

        # Append the new entry to the chat log and update the UI
        self.__write_entry(self.__chat_entries[-1])
        event.text_area.clear()
        self.__resize_message_box()

        # Send the message to the server if the websocket is open
        if self.__ws is not None:
            await self.__ws.send(message)

    def __write_entry(self, entry: ChatEntry) -> None:
        """Writes an entry bubble based on an entry to the chat log"""

        # Calculate width for bubble
        log_width = self.query_one(RichLog).size.width
        usable_width = max(log_width - 6, 20)
        bubble_width = min(60, usable_width)

        # Create the message bubble based on whether the message was sent or received
        message_bubble = Panel(
            Text(entry.message),
            border_style="#7AA9ED" if entry.sent else "white",
            expand=False,
            width=bubble_width,
            padding=(0, 1)
        )
        log_entry = Align(
            message_bubble,
            align="right" if entry.sent else "left"
        )

        # Write the message bubble to the chat log
        self.query_one(RichLog).write(log_entry, expand=True, animate=True)

    def __resize_message_box(self) -> None:
        """Resizes the message box based on its content length."""
        
        # Get the message box that will be resized
        message_box = self.query_one(ChatInput)

        # Calculate the height needed for the message box based on its content
        wrapped_height = max(message_box.wrapped_document.height, 1)
        target_height = min(
            max(wrapped_height + 2, self.MIN_INPUT_HEIGHT),
            self.MAX_INPUT_HEIGHT,
        )

        # Apply the calculated height to the message box
        message_box.styles.height = target_height

if __name__ == "__main__":
    argparser = ArgumentParser()

    argparser.add_argument("--host", default="localhost", help="Server host")
    argparser.add_argument("--port", default=8000, type=int, help="Server port")
    argparser.add_argument("command", help="Command to execute.", choices=["register", "message"])
    argparser.add_argument("username", help="Username to register or message.")
    
    args = argparser.parse_args()

    app = DreamClient(args.host, args.port, args.username)
    app.run()