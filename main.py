import os
import json
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from scanner import scan_ports, scan_ldap
from ai_analyzer import analyze_with_ollama, parse_ai_response
from report import generate_html_report

console = Console()

def banner():
    console.print(Panel.fit("""
[red]
 █████╗ ██████╗     ███████╗███████╗ ██████╗
██╔══██╗██╔══██╗    ██╔════╝██╔════╝██╔════╝
███████║██║  ██║    ███████╗█████╗  ██║     
██╔══██║██║  ██║    ╚════██║██╔══╝  ██║     
██║  ██║██████╔╝    ███████║███████╗╚██████╗
╚═╝  ╚═╝╚═════╝     ╚══════╝╚══════╝ ╚═════╝
[/red]
[cyan]    AI-Powered Active Directory Security Analyzer[/cyan]
[yellow]         Propulsé par Ollama + llama3[/yellow]
[white]      ⚠️  Usage autorisé uniquement ⚠️[/white]
    """, title="[red]AD SEC[/red]", border_style="red"))

def get_target_info():
    console.print("\n[yellow][?] Configuration de la cible[/yellow]")
    target_ip = console.input("[cyan]  DC IP Address : [/cyan]").strip()
    domain = console.input("[cyan]  Domain (ex: corp.local) : [/cyan]").strip()
    username = console.input("[cyan]  Username (Enter pour anonyme) : [/cyan]").strip()
    password = ""
    if username:
        password = console.input("[cyan]  Password : [/cyan]").strip()
    return target_ip, domain, username, password

def main():
    os.makedirs('output', exist_ok=True)
    
    banner()
    
    target_ip, domain, username, password = get_target_info()
    
    console.print(f"\n[green][+] Démarrage de l'analyse sur {target_ip}...[/green]\n")
    
    scan_data = {}
    
    # Scan des ports
    with Progress(
        SpinnerColumn(),
        TextColumn("[cyan]{task.description}[/cyan]"),
        transient=True
    ) as progress:
        task = progress.add_task("Scan des ports AD...", total=None)
        scan_data['ports'] = scan_ports(target_ip)
        progress.update(task, description="✅ Scan ports terminé")
    
    console.print("[green][+] Scan des ports terminé[/green]")
    
    # Scan LDAP
    with Progress(
        SpinnerColumn(),
        TextColumn("[cyan]{task.description}[/cyan]"),
        transient=True
    ) as progress:
        task = progress.add_task("Enumération LDAP...", total=None)
        scan_data['ldap'] = scan_ldap(target_ip, domain, username, password)
        progress.update(task, description="✅ LDAP terminé")
    
    console.print("[green][+] Enumération LDAP terminée[/green]")
    
    # Afficher résumé du scan
    users = scan_data['ldap'].get('users', [])
    groups = scan_data['ldap'].get('groups', [])
    computers = scan_data['ldap'].get('computers', [])
    spn_users = [u['name'] for u in users if u.get('has_spn')]
    
    console.print(f"""
[yellow]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/yellow]
[white]  📊 Résultats du scan :[/white]
  👤 Utilisateurs    : [cyan]{len(users)}[/cyan]
  👥 Groupes         : [cyan]{len(groups)}[/cyan]
  🖥️  Machines        : [cyan]{len(computers)}[/cyan]
  ⚠️  Comptes SPN     : [red]{len(spn_users)}[/red]
[yellow]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/yellow]
    """)
    
    if spn_users:
        console.print(f"[red][!] Comptes Kerberoastables : {', '.join(spn_users)}[/red]")
    
    # Analyse IA
    console.print("\n[yellow][*] Analyse IA en cours (peut prendre 30-60s)...[/yellow]")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[yellow]{task.description}[/yellow]"),
        transient=True
    ) as progress:
        task = progress.add_task("Ollama analyse les données...", total=None)
        ai_raw = analyze_with_ollama(scan_data)
        progress.update(task, description="✅ Analyse IA terminée")
    
    console.print("[green][+] Analyse IA terminée[/green]")
    
    ai_parsed = parse_ai_response(ai_raw)
    
    # Afficher score
    score = ai_parsed.get('score', 50)
    if score >= 80:
        color = "green"
    elif score >= 50:
        color = "yellow"
    else:
        color = "red"
    
    console.print(f"\n[{color}]  🔐 Score de sécurité : {score}/100[/{color}]")
    
    if ai_parsed.get('critical'):
        console.print("\n[red]  🔴 Vulnérabilités critiques :[/red]")
        for v in ai_parsed['critical']:
            console.print(f"  [red]  • {v}[/red]")
    
    if ai_parsed.get('recommendations'):
        console.print("\n[green]  ✅ Top recommandations :[/green]")
        for r in ai_parsed['recommendations'][:3]:
            console.print(f"  [green]  • {r}[/green]")
    
    # Générer rapport HTML
    console.print("\n[yellow][*] Génération du rapport...[/yellow]")
    report_file = generate_html_report(scan_data, ai_parsed, target_ip, domain)
    
    console.print(f"""
[green]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ✅ ANALYSE TERMINÉE !
  📄 Rapport : {report_file}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[/green]
    """)
    
    # Ouvrir le rapport
    open_report = console.input("[cyan]Ouvrir le rapport dans le navigateur ? (o/n) : [/cyan]")
    if open_report.lower() == 'o':
        os.system(f"xdg-open {report_file}")

if __name__ == "__main__":
    main()
