from datetime import datetime
import json
import os
from rich.console import Console

console = Console()

def generate_html_report(scan_data, ai_analysis, target_ip, domain):
    console.print("[cyan][*] Génération du rapport HTML...[/cyan]")
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    filename = f"output/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    
    score = ai_analysis.get('score', 50)
    
    if score >= 80:
        score_color = "#2ecc71"
        score_label = "BON"
    elif score >= 50:
        score_color = "#f39c12"
        score_label = "MOYEN"
    else:
        score_color = "#e74c3c"
        score_label = "CRITIQUE"

    critical_items = ""
    for vuln in ai_analysis.get('critical', []):
        critical_items += f'<li class="critical-item">🔴 {vuln}</li>'
    
    medium_items = ""
    for risk in ai_analysis.get('medium', []):
        medium_items += f'<li class="medium-item">🟡 {risk}</li>'
    
    reco_items = ""
    for reco in ai_analysis.get('recommendations', []):
        reco_items += f'<li class="reco-item">✅ {reco}</li>'

    users_count = len(scan_data.get('ldap', {}).get('users', []))
    groups_count = len(scan_data.get('ldap', {}).get('groups', []))
    computers_count = len(scan_data.get('ldap', {}).get('computers', []))
    ports_count = len(scan_data.get('ports', {}).get('ports', []))

    spn_users = [u['name'] for u in scan_data.get('ldap', {}).get('users', []) if u.get('has_spn')]
    spn_list = ""
    for u in spn_users:
        spn_list += f'<span class="badge-danger">{u}</span> '

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AD Security Report - {domain}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', sans-serif; background: #0a0e1a; color: #e0e6f0; }}
        .header {{ background: linear-gradient(135deg, #1a1f35, #0d1117); padding: 40px; border-bottom: 2px solid #ff4757; }}
        .header h1 {{ font-size: 2.5em; color: #ff4757; letter-spacing: 3px; }}
        .header p {{ color: #8892a4; margin-top: 10px; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 30px; }}
        .score-card {{ background: #1a1f35; border-radius: 15px; padding: 30px; text-align: center; margin: 20px 0; border: 2px solid {score_color}; }}
        .score-number {{ font-size: 5em; font-weight: bold; color: {score_color}; }}
        .score-label {{ font-size: 1.5em; color: {score_color}; letter-spacing: 5px; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin: 20px 0; }}
        .stat-card {{ background: #1a1f35; border-radius: 10px; padding: 20px; text-align: center; border-top: 3px solid #00d2ff; }}
        .stat-number {{ font-size: 2.5em; font-weight: bold; color: #00d2ff; }}
        .stat-label {{ color: #8892a4; font-size: 0.9em; margin-top: 5px; }}
        .section {{ background: #1a1f35; border-radius: 10px; padding: 25px; margin: 20px 0; }}
        .section h2 {{ color: #ff4757; margin-bottom: 15px; font-size: 1.3em; border-bottom: 1px solid #2a2f45; padding-bottom: 10px; }}
        .critical-item {{ color: #ff4757; padding: 8px; border-left: 3px solid #ff4757; margin: 8px 0; list-style: none; background: rgba(255,71,87,0.1); border-radius: 5px; }}
        .medium-item {{ color: #ffa502; padding: 8px; border-left: 3px solid #ffa502; margin: 8px 0; list-style: none; background: rgba(255,165,2,0.1); border-radius: 5px; }}
        .reco-item {{ color: #2ecc71; padding: 8px; border-left: 3px solid #2ecc71; margin: 8px 0; list-style: none; background: rgba(46,204,113,0.1); border-radius: 5px; }}
        .badge-danger {{ background: #ff4757; color: white; padding: 3px 10px; border-radius: 20px; font-size: 0.85em; margin: 3px; display: inline-block; }}
        .summary-box {{ background: rgba(0,210,255,0.1); border: 1px solid #00d2ff; border-radius: 10px; padding: 20px; color: #00d2ff; line-height: 1.8; }}
        .footer {{ text-align: center; padding: 30px; color: #8892a4; border-top: 1px solid #2a2f45; margin-top: 40px; }}
        .target-info {{ display: flex; gap: 20px; margin-top: 15px; }}
        .target-badge {{ background: #2a2f45; padding: 8px 15px; border-radius: 20px; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔐 AD SECURITY ANALYZER</h1>
        <p>Rapport d'analyse de sécurité Active Directory — Propulsé par IA</p>
        <div class="target-info">
            <span class="target-badge">🎯 Cible: {target_ip}</span>
            <span class="target-badge">🏢 Domaine: {domain}</span>
            <span class="target-badge">📅 {timestamp}</span>
        </div>
    </div>

    <div class="container">
        <div class="score-card">
            <div class="score-number">{score}</div>
            <div class="score-label">SCORE DE SÉCURITÉ — {score_label}</div>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number">{users_count}</div>
                <div class="stat-label">👤 Utilisateurs AD</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{groups_count}</div>
                <div class="stat-label">👥 Groupes AD</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{computers_count}</div>
                <div class="stat-label">🖥️ Machines</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{ports_count}</div>
                <div class="stat-label">🔌 Ports ouverts</div>
            </div>
        </div>

        <div class="section">
            <h2>🔴 Vulnérabilités Critiques</h2>
            <ul>{critical_items if critical_items else '<li class="critical-item">Aucune vulnérabilité critique détectée</li>'}</ul>
        </div>

        <div class="section">
            <h2>🟡 Risques Moyens</h2>
            <ul>{medium_items if medium_items else '<li class="medium-item">Aucun risque moyen détecté</li>'}</ul>
        </div>

        <div class="section">
            <h2>⚠️ Comptes Kerberoastables (SPN)</h2>
            <p>{spn_list if spn_list else '<span style="color:#8892a4">Aucun compte avec SPN détecté</span>'}</p>
        </div>

        <div class="section">
            <h2>✅ Recommandations</h2>
            <ul>{reco_items if reco_items else '<li class="reco-item">Aucune recommandation spécifique</li>'}</ul>
        </div>

        <div class="section">
            <h2>📋 Résumé Exécutif</h2>
            <div class="summary-box">{ai_analysis.get('summary', 'Analyse complète disponible dans le rapport détaillé.')}</div>
        </div>
    </div>

    <div class="footer">
        <p>AD Security Analyzer — Généré automatiquement par IA (Ollama/llama3)</p>
        <p style="margin-top:5px; font-size:0.8em;">⚠️ Usage autorisé uniquement sur environnements dont vous avez la permission</p>
    </div>
</body>
</html>"""

    with open(filename, 'w', encoding='utf-8') as f:
        f.write(html)
    
    console.print(f"[green][+] Rapport généré: {filename}[/green]")
    return filename
