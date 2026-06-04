import requests
import json
from rich.console import Console

console = Console()

def analyze_with_ollama(scan_data):
    console.print("[cyan][*] Analyse IA en cours avec Ollama...[/cyan]")
    
    prompt = f"""Tu es un expert en cybersécurité et pentest Active Directory.
Analyse ces résultats de scan AD et identifie :
1. Les vulnérabilités critiques
2. Les risques moyens
3. Les recommandations de sécurité
4. Le score de sécurité global (0-100)

Données du scan :
{json.dumps(scan_data, indent=2)}

Réponds en français avec ce format exact :
SCORE: [nombre]
VULNERABILITES_CRITIQUES: [liste]
RISQUES_MOYENS: [liste]
RECOMMANDATIONS: [liste]
RESUME: [résumé exécutif]
"""
    
    try:
        response = requests.post(
            'http://localhost:11434/api/generate',
            json={
                'model': 'llama3',
                'prompt': prompt,
                'stream': False
            },
            timeout=120
        )
        
        if response.status_code == 200:
            result = response.json()
            return result['response']
        else:
            return "Erreur: Ollama non disponible"
            
    except Exception as e:
        console.print(f"[red][!] Erreur Ollama: {e}[/red]")
        return f"Erreur analyse IA: {e}"

def parse_ai_response(ai_text):
    parsed = {
        'score': 50,
        'critical': [],
        'medium': [],
        'recommendations': [],
        'summary': ''
    }
    
    lines = ai_text.split('\n')
    current_section = None
    
    for line in lines:
        line = line.strip()
        if line.startswith('SCORE:'):
            try:
                parsed['score'] = int(line.split(':')[1].strip().split()[0])
            except:
                parsed['score'] = 50
        elif line.startswith('VULNERABILITES_CRITIQUES:'):
            current_section = 'critical'
            content = line.split(':', 1)[1].strip()
            if content:
                parsed['critical'].append(content)
        elif line.startswith('RISQUES_MOYENS:'):
            current_section = 'medium'
            content = line.split(':', 1)[1].strip()
            if content:
                parsed['medium'].append(content)
        elif line.startswith('RECOMMANDATIONS:'):
            current_section = 'recommendations'
            content = line.split(':', 1)[1].strip()
            if content:
                parsed['recommendations'].append(content)
        elif line.startswith('RESUME:'):
            current_section = 'summary'
            parsed['summary'] = line.split(':', 1)[1].strip()
        elif line and current_section and line.startswith('-'):
            if current_section == 'critical':
                parsed['critical'].append(line[1:].strip())
            elif current_section == 'medium':
                parsed['medium'].append(line[1:].strip())
            elif current_section == 'recommendations':
                parsed['recommendations'].append(line[1:].strip())
    
    return parsed
