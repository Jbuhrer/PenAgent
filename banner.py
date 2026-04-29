from rich.console import Console
from rich.text import Text
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.align import Align
from rich import box

console = Console()

PENAGENT = (
    r" ____  ___  _  _    __    ___  ____  _  _  ____" "\n"
    r"(  _ \( __)( \( )  /__\  / __)( ___)( \( )(_  _)" "\n"
    r" ) __/ ) _)  ) \( /(__)\( (_ \ ) _)  ) \(  )(  " "\n"
    r"(____)(____)(_)\_)(__)(__)\___)(____)(_)\_)(__) "
)

SUBTITLE = "Autonomous Penetration Testing Agent"
WARNING  = "Authorized Lab Environments Only"
VERSION  = "v1.0.0"

# Tiger lines split so we can colorize specific parts
# Format: list of (text, style) segments per line
TIGER_LINES = [
    [("        _             _        ", "bold yellow")],
    [("       / \\__       __/ \\       ", "bold yellow")],
    [("      /  /  \\_____/  \\  \\      ", "bold yellow")],
    [("     /  /   /       \\  \\  \\    ", "bold yellow")],
    [("    /  / /\\/    ^    \\/\\ \\  \\  ", "bold yellow")],
    [("   |  | / \\__       __/ \\ |  | ", "bold yellow")],
    [("   |  |/    _\\     /_    \\|  | ", "bold yellow")],
    [("   |  /   _(", "bold yellow"), ("@@", "bold red"), (")   (", "bold yellow"), ("@@", "bold red"), (")_   \\  | ", "bold yellow")],
    [("   | |   ( \\", "bold yellow"), ("O", "bold red"), ("/     \\", "bold yellow"), ("O", "bold red"), ("/ )   | | ", "bold yellow")],
    [("   | |    `._       _.'    | | ", "bold yellow")],
    [("   | |  ", "bold yellow"), ("///", "bold red"), ("  \\_____/  ", "bold yellow"), ("\\\\\\", "bold red"), (" | | ", "bold yellow")],
    [("   | |  ", "bold yellow"), ("///", "bold red"), ("  /  ___  \\ ", "bold yellow"), ("\\\\\\", "bold red"), (" | | ", "bold yellow")],
    [("   | |      / /     \\ \\    | | ", "bold yellow")],
    [("   | |     | |  /w\\  | |   | | ", "bold yellow")],
    [("   | |      \\ \\_____/ /    | | ", "bold yellow")],
    [("   | |   _.-'         '-._  | | ", "bold yellow")],
    [("   | |  / /|           |\\ \\ | | ", "bold yellow")],
    [("   | | | / |           | \\ || | ", "bold yellow")],
    [("   | |  V  | V       V |  V | | ", "bold yellow")],
    [("   | |     |_|_|_|_|_|_|    | | ", "bold yellow")],
    [("    \\ \\____________________/ /  ", "bold yellow")],
    [("     \\______________________/   ", "bold yellow")],
]


def print_banner():
    console.print()
    console.print(Align.center(Text(PENAGENT, style="bold yellow")))
    console.print()

    # Print tiger with colored segments
    for line_segments in TIGER_LINES:
        t = Text()
        for text, style in line_segments:
            t.append(text, style=style)
        console.print(Align.center(t))

    console.print()
    line = (
        Text(SUBTITLE, style="bold purple") +
        Text("  |  ", style="dim") +
        Text(WARNING,  style="dim white") +
        Text(f"  {VERSION}", style="dim cyan")
    )
    console.print(Align.center(line))
    console.print()
    console.print(Align.center(Text("─" * 62, style="purple")))
    console.print()


def print_scan_header(target_ip: str, scan_file: str):
    tbl = Table.grid(padding=(0, 2))
    tbl.add_column(style="dim cyan", justify="right")
    tbl.add_column(style="white")
    tbl.add_row("TARGET",    target_ip)
    tbl.add_row("SCAN FILE", scan_file)
    tbl.add_row("MODE",      "Full Autonomous  [recon → exploit → report]")
    tbl.add_row("SCOPE",     "Authorized lab environment only")
    console.print(Panel(
        tbl,
        title="[bold yellow] MISSION PARAMETERS [/bold yellow]",
        border_style="yellow",
        padding=(1, 2),
    ))
    console.print()


def print_phase(phase_num: int, phase_name: str, detail: str = ""):
    colors = {1: "cyan", 2: "blue", 3: "red", 4: "green"}
    c  = colors.get(phase_num, "white")
    dt = f"  [dim]{detail}[/dim]" if detail else ""
    console.print(
        f"  [bold {c}]◆ PHASE {phase_num}[/bold {c}]"
        f"  [{c}]{phase_name}[/{c}]{dt}"
    )


def print_shell_drop(target_ip: str):
    console.print()
    line = Text()
    line.append("  [+] ", style="bold green")
    line.append("ROOT SHELL ACQUIRED  ", style="bold white")
    line.append(target_ip, style="bold cyan")
    console.print(line)
    console.print(Text("      uid=0(root) gid=0(root) groups=0(root)", style="dim green"))
    console.print()
    console.print(Panel(
        Text("  Dropping you in.  Type 'exit' to return to PenAgent.\n", style="dim white"),
        title="[bold green] INTERACTIVE SHELL [/bold green]",
        border_style="green",
    ))


def print_report_summary(findings: list, report_path: str, elapsed: float):
    console.print()
    tbl = Table(
        title="FINDINGS SUMMARY",
        box=box.SIMPLE_HEAD,
        border_style="dim yellow",
        header_style="bold cyan",
        show_lines=False,
        padding=(0, 1),
    )
    tbl.add_column("#",        style="dim", width=3)
    tbl.add_column("Finding",  min_width=34)
    tbl.add_column("Severity", width=10)
    tbl.add_column("CVSS",     width=6)
    tbl.add_column("CVE",      width=18, style="dim cyan")
    sev_styles = {
        "CRITICAL": "bold red",
        "HIGH":     "bright_red",
        "MEDIUM":   "yellow",
        "LOW":      "green",
    }
    for i, f in enumerate(findings, 1):
        cvss = f.get("cvss", 0.0)
        if   cvss >= 9.0: sev = "CRITICAL"
        elif cvss >= 7.0: sev = "HIGH"
        elif cvss >= 4.0: sev = "MEDIUM"
        else:             sev = "LOW"
        tbl.add_row(
            str(i),
            f.get("title", "Unknown"),
            f"[{sev_styles[sev]}]{sev}[/{sev_styles[sev]}]",
            f"{cvss:.1f}",
            f.get("cve", "—"),
        )
    console.print(tbl)
    console.print()
    stats = Table.grid(padding=(0, 3))
    stats.add_column(style="dim")
    stats.add_column(style="bold white")
    stats.add_row("Report saved to", f"[cyan]{report_path}[/cyan]")
    stats.add_row("Total findings",  str(len(findings)))
    stats.add_row("Elapsed time",    f"{elapsed:.1f}s")
    console.print(stats)
    console.print()


def spinner_context(message: str):
    return Progress(
        SpinnerColumn(spinner_name="dots", style="yellow"),
        TextColumn(f"[dim]{message}[/dim]"),
        transient=True,
        console=console,
    )


def status(msg: str):
    console.print(f"  [dim yellow]›[/dim yellow] [dim]{msg}[/dim]")

def success(msg: str):
    console.print(f"  [bold green][+][/bold green] {msg}")

def warn(msg: str):
    console.print(f"  [bold yellow][!][/bold yellow] {msg}")

def error(msg: str):
    console.print(f"  [bold red][-][/bold red] {msg}")
