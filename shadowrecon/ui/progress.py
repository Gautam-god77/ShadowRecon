import time
from datetime import datetime

from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich import box

console = Console()


class EventStream:

    def __init__(self):
        self.events = []

    def add(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")

        self.events.append(
            f"[dim][{timestamp}][/dim] {message}"
        )

        if len(self.events) > 12:
            self.events.pop(0)

    def render(self):

        table = Table(
            box=None,
            show_header=False,
            expand=True,
        )

        for event in self.events:
            table.add_row(event)

        return table

    def show(self, messages):

        with Live(
            self.render(),
            refresh_per_second=8,
            console=console,
        ) as live:

            for message in messages:

                self.add(message)

                live.update(self.render())

                time.sleep(0.5)
