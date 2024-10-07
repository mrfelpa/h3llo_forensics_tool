import subprocess
import logging
import argparse
import json
from datetime import datetime
import os
import sys
from typing import Dict, List, Optional, Tuple
import platform
import socket
import re
import time
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskID
from rich.panel import Panel
from rich.live import Live
from rich.layout import Layout
from rich.text import Text
from rich.traceback import install
from rich.prompt import Confirm

install()

class WindowsForensicTool:
    def __init__(self, log_file: str = "forensic_scan.log"):
        self.console = Console()
        self.setup_logging(log_file)
        self.verify_windows_environment()
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'system_info': {},
            'network_info': {},
            'active_hosts': []
        }
        
    def setup_logging(self, log_file: str) -> None:
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        
    def verify_windows_environment(self) -> None:
        if platform.system().lower() != 'windows':
            self.console.print("[bold red]Error: This tool is designed for Windows systems only.[/bold red]")
            sys.exit(1)

    def run_command(self, command: str) -> Tuple[str, Optional[str]]:
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True,
                text=True
            )
            stdout, stderr = process.communicate(timeout=30)
            return stdout.strip(), stderr
        except subprocess.TimeoutExpired:
            return "", "Command timed out"
        except Exception as e:
            return "", str(e)

    def get_network_info(self, progress: Progress, task: TaskID) -> Dict:
        network_info = {}
        
        commands = {
            'Network Shares': 'net share',
            'Active Connections': 'netstat -naob',
            'Routing Table': 'route print',
            'ARP Cache': 'arp -a',
            'IP Configuration': 'ipconfig /all'
        }
        
        subtask_id = progress.add_task("[cyan]Collecting network information...", total=len(commands))
        
        for key, command in commands.items():
            progress.update(task, description=f"[cyan]Executing: {key}")
            output, error = self.run_command(command)
            if not error:
                network_info[key] = output
            progress.update(subtask_id, advance=1)
            
        progress.update(task, completed=True)
        return network_info

    def get_system_info(self, progress: Progress, task: TaskID) -> Dict:
        system_info = {}
        
        commands = {
            'Hostname': 'hostname',
            'System Info': 'systeminfo',
            'User Accounts': 'net users',
            'Admin Group': 'net localgroup administrators',
            'Running Services': 'wmic service list brief | findstr "Running"'
        }
        
        subtask_id = progress.add_task("[cyan]Collecting system information...", total=len(commands))
        
        for key, command in commands.items():
            progress.update(task, description=f"[cyan]Executing: {key}")
            output, error = self.run_command(command)
            if not error:
                system_info[key] = output
            progress.update(subtask_id, advance=1)
            
        progress.update(task, completed=True)
        return system_info

    def scan_network(self, subnet: str, progress: Progress, task: TaskID) -> List[str]:
        active_hosts = []
        
        subtask_id = progress.add_task(f"[cyan]Scanning subnet {subnet}", total=254)
        
        for i in range(1, 255):
            ip = f"{subnet}.{i}"
            progress.update(task, description=f"[cyan]Testing IP: {ip}")
            command = f"ping -n 1 -w 200 {ip}"
            output, _ = self.run_command(command)
            
            if "Reply from" in output:
                active_hosts.append(ip)
                
            progress.update(subtask_id, advance=1)
            
        progress.update(task, completed=True)
        return active_hosts

    def create_results_table(self) -> Table:
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Category", style="dim")
        table.add_column("Details")
        
        for key, value in self.results['system_info'].items():
            summary = value.split('\n')[0] if value else 'N/A'
            table.add_row(key, summary)
        
        for key, value in self.results['network_info'].items():
            summary = value.split('\n')[0] if value else 'N/A'
            table.add_row(key, summary)
        
        if self.results['active_hosts']:
            table.add_row("Active Hosts", ', '.join(self.results['active_hosts']))
        
        return table

    def export_results(self, output_file: str) -> None:
        try:
            with open(output_file, 'w') as f:
                json.dump(self.results, f, indent=4)
            self.console.print(f"[green]Results exported to {output_file}[/green]")
        except Exception as e:
            self.console.print(f"[bold red]Error exporting results: {str(e)}[/bold red]")

    def run_scan(self, subnet: Optional[str] = None, output_file: str = "forensic_results.json") -> None:
        layout = Layout()
        layout.split_column(
            Layout(name="header"),
            Layout(name="main"),
            Layout(name="footer")
        )
        
        layout["header"].update(Panel(
            "[bold blue]Windows Forensic Tool[/bold blue]\n"
            "[cyan]Starting forensic analysis...[/cyan]"
        ))
        
        with Live(layout, refresh_per_second=4):
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                console=self.console
            ) as progress:
                sys_task = progress.add_task("[cyan]Collecting system information...", total=100)
                self.results['system_info'] = self.get_system_info(progress, sys_task)
                
                
                net_task = progress.add_task("[cyan]Collecting network information...", total=100)
                self.results['network_info'] = self.get_network_info(progress, net_task)
                
                
                if subnet:
                    scan_task = progress.add_task(f"[cyan]Scanning network {subnet}...", total=100)
                    self.results['active_hosts'] = self.scan_network(subnet, progress, scan_task)
        
        results_table = self.create_results_table()
        layout["main"].update(results_table)
        
        summary_text = Text()
        summary_text.append("\nAnalysis Summary:\n", style="bold green")
        summary_text.append(f"• {len(self.results['system_info'])} system information items collected\n")
        summary_text.append(f"• {len(self.results['network_info'])} network information items collected\n")
        if subnet:
            summary_text.append(f"• {len(self.results['active_hosts'])} active hosts found\n")
        
        layout["footer"].update(Panel(summary_text))
        
        if Confirm.ask("Do you want to export the results to a JSON file?"):
            self.export_results(output_file)

def main():
    console = Console()
    
    try:
        console.print(Panel.fit(
            "[bold blue]H3LLO[/bold blue]\n"
            "[cyan]An advanced forensic tool for Windows[/cyan]"
        ))
        
        parser = argparse.ArgumentParser(description="Windows Forensic Tool")
        parser.add_argument("--subnet", help="Subnet to scan (e.g., 192.168.1)")
        parser.add_argument("--output", default="forensic_results.json", help="Output file for results")
        parser.add_argument("--log", default="forensic_scan.log", help="Log file location")
        args = parser.parse_args()
        
        if not os.path.exists(os.path.dirname(args.output)):
            os.makedirs(os.path.dirname(args.output))
            
        tool = WindowsForensicTool(log_file=args.log)
        
        if Confirm.ask("Start forensic analysis?"):
            tool.run_scan(subnet=args.subnet, output_file=args.output)
            
    except KeyboardInterrupt:
        console.print("\n[bold red]Analysis interrupted by user.[/bold red]")
    except Exception as e:
        console.print(f"[bold red]Unexpected error: {str(e)}[/bold red]")
        console.print_exception()

if __name__ == "__main__":
    main()
