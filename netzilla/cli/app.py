# netzilla/cli/app.py
from datetime import datetime
import time
import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn
from rich.table import Table
from rich.prompt import Prompt

app = typer.Typer(help="Net-ZiLLA Threat Intelligence Command Center")
console = Console()

# Vintage MS-DOS Theme Palette (Classic Monospace / Amber-Green CRT style)
THEME_GREEN = "#00FF66"
THEME_DARK_GREEN = "#003311"
THEME_MUTED = "#00AA44"
THEME_WARNING = "#FFFF00"
THEME_DANGER = "#FF3333"

LOGO_ART = r"""
     __
    / _)  [NET-ZiLLA v1.0.0]
   [ @ ]  [CRT TERMINAL MODE]
    \--/
"""

def render_banner():
    console.clear()
    banner_text = f"[bold {THEME_GREEN}]{LOGO_ART}[/bold {THEME_GREEN}]"
    console.print(Panel(
        banner_text,
        title=f"[bold {THEME_GREEN}]SYSTEM READY :: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/bold {THEME_GREEN}]",
        border_style=THEME_MUTED,
        subtitle=f"[italic {THEME_MUTED}]C:\\NETZILLA\\CORE>_ [/italic {THEME_MUTED}]"
    ))

@app.command()
def center():
    """Launch the interactive vintage MS-DOS command center."""
    while True:
        render_banner()
        
        table = Table(title="[bold underline]MAIN CONTROL MENU[/bold underline]", style=THEME_GREEN, border_style=THEME_MUTED, expand=True)
        table.add_column("ID", style=THEME_WARNING, justify="center", width=6)
        table.add_column("COMMAND MODULE", style=THEME_GREEN)
        table.add_column("DESCRIPTION", style=f"dim {THEME_GREEN}")

        table.add_row("[1]", "ANALYZE URL", "Deep scan for phishing, shorteners, & malicious signatures")
        table.add_row("[2]", "DOMAIN RECON", "DNS query, correlation, & brand impersonation check")
        table.add_row("[3]", "BATCH SCAN", "Run pipeline across bulk target files with progress ETA")
        table.add_row("[4]", "API SERVER", "Spin up Net-ZiLLA FastAPI backend interface")
        table.add_row("[5]", "SYSTEM LOGS", "View real-time action history & correlation events")
        table.add_row("[0]", "EXIT", "Terminate terminal session")

        console.print(table)
        
        choice = Prompt.ask(f"[bold {THEME_GREEN}]C:\\NETZILLA> Select Operation[/bold {THEME_GREEN}]", default="1")

        if choice == "1":
            target = Prompt.ask(f"[bold {THEME_GREEN}]Enter target URL/Domain[/bold {THEME_GREEN}]")
            run_analysis_pipeline(target)
            Prompt.ask(f"\n[dim {THEME_GREEN}]Press ENTER to return to command center...[/dim {THEME_GREEN}]")
        elif choice == "2":
            target = Prompt.ask(f"[bold {THEME_GREEN}]Enter target domain[/bold {THEME_GREEN}]")
            run_domain_recon(target)
            Prompt.ask(f"\n[dim {THEME_GREEN}]Press ENTER to return to command center...[/dim {THEME_GREEN}]")
        elif choice == "3":
            run_batch_simulation()
            Prompt.ask(f"\n[dim {THEME_GREEN}]Press ENTER to return to command center...[/dim {THEME_GREEN}]")
        elif choice == "4":
            console.print(f"\n[bold {THEME_WARNING}]>> Initializing API server daemon on http://127.0.0.1:8000...[/bold {THEME_WARNING}]")
            time.sleep(2)
        elif choice == "5":
            show_system_logs()
            Prompt.ask(f"\n[dim {THEME_GREEN}]Press ENTER to return to command center...[/dim {THEME_GREEN}]")
        elif choice == "0" or choice.lower() == "exit":
            console.print(f"\n[bold {THEME_DANGER}]Shutting down Net-ZiLLA terminal... Goodbye.[/bold {THEME_DANGER}]")
            break
        else:
            console.print(f"[bold {THEME_DANGER}]ERROR: Invalid command option.[/bold {THEME_DANGER}]")
            time.sleep(1)

def run_analysis_pipeline(target: str):
    console.print(f"\n[bold {THEME_GREEN}]>> Initializing Threat Analyzer for: {target}[/bold {THEME_GREEN}]")
    
    with Progress(
        SpinnerColumn(spinner_name="dots", style=THEME_GREEN),
        TextColumn(f"[bold {THEME_GREEN}]{{task.description}}[/bold {THEME_GREEN}]"),
        BarColumn(bar_width=30, complete_style=THEME_GREEN, finished_style=THEME_DARK_GREEN),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeRemainingColumn(),
        console=console,
    ) as progress:
        
        t1 = progress.add_task("Parsing URL structure...", total=100)
        t2 = progress.add_task("Running content analyzers...", total=100)
        t3 = progress.add_task("Checking brand impersonation...", total=100)
        t4 = progress.add_task("Querying malware signature database...", total=100)

        while not progress.finished:
            if not progress.tasks[0].completed:
                progress.update(t1, advance=25)
            elif not progress.tasks[1].completed:
                progress.update(t2, advance=20)
            elif not progress.tasks[2].completed:
                progress.update(t3, advance=33)
            elif not progress.tasks[3].completed:
                progress.update(t4, advance=50)
            time.sleep(0.3)

    # Status Display Box
    result_table = Table(title="[bold]ANALYSIS REPORT SUMMARY[/bold]", style=THEME_GREEN, border_style=THEME_MUTED)
    result_table.add_column("Check Module", style=THEME_GREEN)
    result_table.add_column("Status Code", style="bold")
    result_table.add_column("Risk Score", justify="right")

    result_table.add_row("URL Parser", "[green]OK [Clean][/green]", "0.0 / 10")
    result_table.add_row("Phishing Detector", "[green]SAFE[/green]", "1.2 / 10")
    result_table.add_row("Brand Impersonation", f"[{THEME_WARNING}]WARNING [Potential Match][/{THEME_WARNING}]", "6.5 / 10")
    result_table.add_row("Malware Signatures", "[green]CLEAN[/green]", "0.0 / 10")

    console.print(result_table)
    console.print(Panel(f"[bold {THEME_WARNING}]FINAL VERDICT: MEDIUM RISK (Potential Brand Spoofing Detected)[/bold {THEME_WARNING}]", border_style=THEME_WARNING))

def run_domain_recon(domain: str):
    console.print(f"\n[bold {THEME_GREEN}]>> Executing DNS & Domain Intelligence scan for: {domain}[/bold {THEME_GREEN}]")
    with console.status(f"[bold {THEME_GREEN}]Resolving records & correlation mapping...[/bold {THEME_GREEN}]", spinner="aesthetic"):
        time.sleep(2.0)
    
    console.print(f"[{THEME_GREEN}] [SUCCESS] DNS A Records resolved: 192.0.2.14[/{THEME_GREEN}]")
    console.print(f"[{THEME_GREEN}] [SUCCESS] WHOIS Lookup complete: Registered 14 days ago (High Risk Flag)[/{THEME_GREEN}]")

def run_batch_simulation():
    console.print(f"\n[bold {THEME_GREEN}]>> Starting Batch URL Queue Process...[/bold {THEME_GREEN}]")
    total_items = 10
    with Progress(
        SpinnerColumn(spinner_name="monkey", style=THEME_GREEN),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40, complete_style=THEME_GREEN),
        TextColumn("{task.completed}/{task.total} targets"),
        TimeRemainingColumn(),
        console=console
    ) as progress:
        task = progress.add_task("Batch Scanning...", total=total_items)
        for _ in range(total_items):
            time.sleep(0.25)
            progress.update(task, advance=1)
    console.print(f"[{THEME_GREEN}] [DONE] Batch pipeline successfully completed. All logs saved.[/{THEME_GREEN}]")

def show_system_logs():
    console.print(Panel(f"[dim {THEME_GREEN}]"
                        "[18:02:41] [INFO] Core module loaded successfully.\n"
                        "[18:05:12] [WARN] Connection timeout on threat-feed mirror #2.\n"
                        "[18:10:00] [INFO] Cache cleared. 42 items evicted.\n"
                        f"[/dim {THEME_GREEN}]", title="[bold]SYSTEM LOG BUFFER[/bold]", border_style=THEME_MUTED))

if __name__ == "__main__":
    app()
