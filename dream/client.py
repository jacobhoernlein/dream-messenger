from dataclasses import dataclass
from datetime import datetime

from rich.align import Align
from rich.panel import Panel
from rich.text import Text
from textual import events
from textual.app import App, ComposeResult
from textual.widgets import (
    Header, 
    Footer,
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
    SUB_TITLE = "Chat with {user}"

    def __init__(self) -> None:
        super().__init__()
        self.__chat_entries: list[ChatEntry] = []

    def compose(self) -> ComposeResult:
        yield Header()
        yield RichLog(auto_scroll=True, wrap=True, min_width=24)
        yield ChatInput(placeholder="Message {user}...", id="message-box")
        yield Footer()

    def on_mount(self) -> None:
        self.__resize_message_box()
        self.query_one(ChatInput).focus()

    def on_ready(self) -> None:
        ...

    def on_text_area_changed(self, _: TextArea.Changed) -> None:
        self.__resize_message_box()

    def on_resize(self, _: events.Resize) -> None:
        if self.is_mounted:
            self.query_one(RichLog).clear()
            for entry in self.__chat_entries:
                self.__write_entry(entry)

    async def on_chat_input_submitted(self, event: ChatInput.Submitted) -> None:
        
        message = event.value.strip()
        if not message:
            return

        message_time = datetime.now().strftime("[%H:%M:%S]")
        self.__chat_entries.append(
            ChatEntry(
                message=message,
                sent=True,
                timestamp=message_time
            )
        )

        self.__write_entry(self.__chat_entries[-1])
        event.text_area.clear()
        self.__resize_message_box()

    def __write_entry(self, entry: ChatEntry) -> None:
        """Writes an entry bubble based on an entry to the chat log"""

        # Calculate width for bubble
        log_width = self.query_one(RichLog).size.width
        usable_width = max(log_width - 6, 20)
        bubble_width = min(60, usable_width)

        # Ensure enough space for timestamp
        pw = 14 - len(entry.message)
        if pw > 0:
            entry.message += " " * pw

        if entry.sent:
            message_bubble = Align.right(
                Panel(
                    Text(entry.message),
                    subtitle=entry.timestamp,
                    subtitle_align="right",
                    border_style="green",
                    expand=False,
                    width=bubble_width,
                    padding=(0, 1),
                )
            )
        else:
            message_bubble = Align.left(
                Panel(
                    Text(entry.message),
                    subtitle=entry.timestamp,
                    subtitle_align="left",
                    border_style="white",
                    expand=False,
                    width=bubble_width,
                    padding=(0, 1),
                )
            )

        self.query_one(RichLog).write(message_bubble, expand=True)

    def __resize_message_box(self) -> None:
        """Resizes the message box based on its content length."""
        
        message_box = self.query_one(ChatInput)

        wrapped_height = max(message_box.wrapped_document.height, 1)
        target_height = min(
            max(wrapped_height + 2, self.MIN_INPUT_HEIGHT),
            self.MAX_INPUT_HEIGHT,
        )

        message_box.styles.height = target_height


app = DreamClient()
app.run()