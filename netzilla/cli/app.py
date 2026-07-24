"""
Net-ZiLLA CLI – Vintage CRT Terminal Interface
Amber/Green dual‑phosphor aesthetic, no animation.
"""

import sys
import time
from datetime import datetime
import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TimeRemainingColumn,
)
from rich.table import Table
from rich.prompt import Prompt
from rich.text import Text

app = typer.Typer(help="Net-ZiLLA Threat Intelligence Command Center")
console = Console()

# ---------------------------------------------------------------------------
# Vintage dual‑phosphor palette
# ---------------------------------------------------------------------------
AMBER       = "#FF8C00"
AMBER_DIM   = "#B85C00"
GREEN       = "#00FF66"
GREEN_DIM   = "#003311"
WARNING     = "#FFFF00"
DANGER      = "#FF3333"

HEADER = """
█▄░█ █▀▀ ▀█▀ █▀▀ █░█ █ █░░ █░░ █▀▀
█░▀█ █▀▀ ░█░ ▄▄█ █▀▄ █ █░░ █░░ █▀▀
▀░░▀ ▀▀▀ ░▀░ ▀▀▀ ▀░▀ ▀ ▀▀▀ ▀▀▀ ▀▀▀
"""

MSG = {
    "menu_title": "MAIN CONTROL MENU",
    "menu_items": {
        "1": ("ANALYZE URL", "Deep scan for phishing, shorteners & malicious signatures"),
        "2": ("DOMAIN RECON", "DNS query, correlation & brand impersonation check"),
        "3": ("BATCH SCAN", "Run pipeline across bulk target files with progress"),
        "4": ("API SERVER", "Spin up Net-ZiLLA FastAPI backend interface"),
        "5": ("SYSTEM LOGS", "View real-time action history & correlation events"),
        "0": ("EXIT", "Terminate terminal session"),
    },
    "prompt_choice": "C:\\NETZILLA> Select Operation",
    "prompt_url": "Enter target URL/Domain",
    "prompt_domain": "Enter target domain",
    "press_enter": "Press ENTER to return to command center...",
    "shutdown": "Shutting down Net-ZiLLA terminal... Goodbye.",
    "invalid_option": "ERROR: Invalid command option.",
    "api_start": ">> Initializing API server daemon on http://127.0.0.1:8000...",
    "analysis_start": lambda t: f">> Initializing Threat Analyzer for: {t}",
    "recon_start": lambda d: f">> Executing DNS & Domain Intelligence scan for: {d}",
    "batch_start": ">> Starting Batch URL Queue Process...",
    "recon_status": "Resolving records & correlation mapping...",
    "recon_a_record": "[SUCCESS] DNS A Records resolved: 192.0.2.14",
    "recon_whois": "[SUCCESS] WHOIS Lookup complete: Registered 14 days ago (High Risk Flag)",
    "batch_done": "[DONE] Batch pipeline successfully completed. All logs saved.",
    "log_content": (
        "[18:02:41] [INFO] Core module loaded successfully.\n"
        "[18:05:12] [WARN] Connection timeout on threat-feed mirror #2.\n"
        "[18:10:00] [INFO] Cache cleared. 42 items evicted.\n"
    ),
    "verdict": "FINAL VERDICT: MEDIUM RISK (Potential Brand Spoofing Detected)",
}

SIMULATED_TASKS = [
    {"name": "Parsing URL structure...", "steps": 4, "delay": 0.3},
    {"name": "Running content analyzers...", "steps": 5, "delay": 0.3},
    {"name": "Checking brand impersonation...", "steps": 3, "delay": 0.3},
    {"name": "Querying malware signature database...", "steps": 2, "delay": 0.3},
]


# ---------------------------------------------------------------------------
# Instant banner – no animation, no freezing
# ---------------------------------------------------------------------------
def render_banner() -> None:
    """Clear screen and display the vintage header instantly."""
    console.clear()
    console.print(Text(HEADER, style=f"bold {AMBER}"))

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
    console.print(
        Panel(
            Text(f"SYSTEM READY :: {timestamp}", style=f"bold {AMBER}"),
            border_style=GREEN,
            subtitle=Text("C:\\NETZILLA\\CORE>_", style=f"italic {AMBER_DIM}"),
        )
    )


def build_menu_table() -> Table:
    """Return the main command menu table."""
    table = Table(
        title=Text(MSG["menu_title"], style=f"bold underline {AMBER}"),
        style=AMBER,
        border_style=GREEN,
        expand=True,
    )
    table.add_column("ID", style=GREEN, justify="center", width=6)
    table.add_column("COMMAND MODULE", style=f"bold {AMBER}")
    table.add_column("DESCRIPTION", style=f"dim {AMBER_DIM}")

    for key, (module, desc) in MSG["menu_items"].items():
        table.add_row(f"[{key}]", module, desc)
    return table


def get_user_choice() -> str:
    """Prompt for the menu selection."""
    return Prompt.ask(
        f"[bold {AMBER}]{MSG['prompt_choice']}[/bold {AMBER}]", default="1"
    )


def wait_for_enter() -> None:
    """Pause until the user presses ENTER."""
    Prompt.ask(f"\n[dim {AMBER_DIM}]{MSG['press_enter']}[/dim {AMBER_DIM}]")


def run_simulated_pipeline(tasks: list[dict]) -> None:
    """Show concurrent progress bars for a simulated analysis pipeline."""
    with Progress(
        SpinnerColumn(spinner_name="dots", style=GREEN),
        TextColumn(f"[bold {AMBER}]{{task.description}}[/bold {AMBER}]"),
        BarColumn(bar_width=30, complete_style=GREEN, finished_style=GREEN_DIM),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeRemainingColumn(),
        console=console,
    ) as progress:
        progress_tasks = []
        for tdef in tasks:
            progress_tasks.append({
                "id": progress.add_task(tdef["name"], total=100),
                "steps": tdef["steps"],
                "increment": 100 / tdef["steps"],
            })

        all_complete = False
        while not all_complete:
            all_complete = True
            for pt in progress_tasks:
                task_id = pt["id"]
                if not progress.tasks[task_id].completed:
                    all_complete = False
                    progress.update(task_id, advance=pt["increment"])
            time.sleep(0.1)   # small fixed delay for visual smoothness


def build_result_table() -> Table:
    """Return a mock analysis report table."""
    table = Table(
        title=Text("ANALYSIS REPORT SUMMARY", style=f"bold {AMBER}"),
        style=AMBER,
        border_style=GREEN,
    )
    table.add_column("Check Module", style=AMBER)
    table.add_column("Status Code", style="bold")
    table.add_column("Risk Score", justify="right", style=GREEN)

    table.add_row("URL Parser", f"[{GREEN}]OK [Clean][/{GREEN}]", "0.0 / 10")
    table.add_row("Phishing Detector", f"[{GREEN}]SAFE[/{GREEN}]", "1.2 / 10")
    table.add_row(
        "Brand Impersonation",
        f"[{WARNING}]WARNING [Potential Match][/{WARNING}]",
        "6.5 / 10",
    )
    table.add_row("Malware Signatures", f"[{GREEN}]CLEAN[/{GREEN}]", "0.0 / 10")
    return table


# ---------------------------------------------------------------------------
# Command handlers (each is self‑contained and fully documented)
# ---------------------------------------------------------------------------
def handle_analyze_url() -> None:
    """Run the URL threat analysis simulation."""
    target = Prompt.ask(f"[bold {AMBER}]{MSG['prompt_url']}[/bold {AMBER}]")
    console.print(f"\n[bold {AMBER}]{MSG['analysis_start'](target)}[/bold {AMBER}]")
    run_simulated_pipeline(SIMULATED_TASKS)
    console.print(build_result_table())
    console.print(
        Panel(Text(MSG["verdict"], style=f"bold {WARNING}"), border_style=WARNING)
    )


def handle_domain_recon() -> None:
    """Simulate a DNS / WHOIS domain intelligence scan."""
    domain = Prompt.ask(f"[bold {AMBER}]{MSG['prompt_domain']}[/bold {AMBER}]")
    console.print(f"\n[bold {AMBER}]{MSG['recon_start'](domain)}[/bold {AMBER}]")
    with console.status(
        f"[bold {AMBER}]{MSG['recon_status']}[/bold {AMBER}]", spinner="aesthetic"
    ):
        time.sleep(2.0)
    console.print(f"[{GREEN}] {MSG['recon_a_record']}[/{GREEN}]")
    console.print(f"[{GREEN}] {MSG['recon_whois']}[/{GREEN}]")


def handle_batch_scan() -> None:
    """Simulate a batch URL scanning progress."""
    console.print(f"\n[bold {AMBER}]{MSG['batch_start']}[/bold {AMBER}]")
    total_items = 10
    with Progress(
        SpinnerColumn(spinner_name="monkey", style=GREEN),
        TextColumn(f"[bold {AMBER}]{{task.description}}[/bold {AMBER}]"),
        BarColumn(bar_width=40, complete_style=GREEN),
        TextColumn("{task.completed}/{task.total} targets"),
        TimeRemainingColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Batch Scanning...", total=total_items)
        for _ in range(total_items):
            time.sleep(0.25)
            progress.update(task, advance=1)
    console.print(f"[{GREEN}] {MSG['batch_done']}[/{GREEN}]")


def handle_api_server() -> None:
    """Print an API server startup message (simulation)."""
    console.print(f"\n[bold {AMBER}]{MSG['api_start']}[/bold {AMBER}]")
    time.sleep(2)


def handle_system_logs() -> None:
    """Display a mock real‑time system log buffer."""
    console.print(
        Panel(
            Text(MSG["log_content"], style=f"dim {GREEN}"),
            title=Text("SYSTEM LOG BUFFER", style=f"bold {AMBER}"),
            border_style=GREEN,
        )
    )


def handle_shutdown() -> bool:
    """Print shutdown message and return True to break the main loop."""
    console.print(f"\n[bold {DANGER}]{MSG['shutdown']}[/bold {DANGER}]")
    return True


# Dispatch table: choice → (handler, needs_pause)
MENU_ACTIONS = {
    "1": (handle_analyze_url, True),
    "2": (handle_domain_recon, True),
    "3": (handle_batch_scan, True),
    "4": (handle_api_server, False),
    "5": (handle_system_logs, True),
    "0": (handle_shutdown, False),
}


# ---------------------------------------------------------------------------
# Main command – graceful shutdown on Ctrl+C
# ---------------------------------------------------------------------------
@app.command()
def center() -> None:
    """Launch the interactive vintage command center (press Ctrl+C to exit)."""
    while True:
        try:
            render_banner()
        except KeyboardInterrupt:
            handle_shutdown()
            break

        console.print(build_menu_table())
        choice = get_user_choice()

        if choice.lower() == "exit":
            choice = "0"

        action_entry = MENU_ACTIONS.get(choice)
        if action_entry is None:
            console.print(f"[bold {DANGER}]{MSG['invalid_option']}[/bold {DANGER}]")
            time.sleep(1)
            continue

        handler, needs_pause = action_entry
        should_quit = handler()
        if should_quit:
            break
        if needs_pause:
            wait_for_enter()


if __name__ == "__main__":
    if len(sys.argv) == 1:
        try:
            center()
        except KeyboardInterrupt:
            # Already handled inside – extra safety
            pass
    else:
        app()
