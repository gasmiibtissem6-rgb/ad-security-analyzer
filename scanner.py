import nmap
import ldap3
import socket
from rich.console import Console

console = Console()

def scan_ports(target_ip):
    console.print(f"[cyan][*] Scan Nmap sur {target_ip}...[/cyan]")
    nm = nmap.PortScanner()
    nm.scan(target_ip, '53,88,135,139,389,445,464,636,3268,3269', '-sV')
    results = {}
    for host in nm.all_hosts():
        results['host'] = host
        results['ports'] = []
        for proto in nm[host].all_protocols():
            for port in nm[host][proto].keys():
                state = nm[host][proto][port]['state']
                service = nm[host][proto][port]['name']
                results['ports'].append({
                    'port': port,
                    'state': state,
                    'service': service
                })
    return results

def scan_ldap(target_ip, domain, username="", password=""):
    console.print(f"[cyan][*] Scan LDAP sur {target_ip}...[/cyan]")
    results = {
        'users': [],
        'groups': [],
        'computers': [],
        'password_policy': {}
    }
    try:
        server = ldap3.Server(target_ip, get_info=ldap3.ALL)
        if username and password:
            conn = ldap3.Connection(server, user=f"{domain}\\{username}", password=password, auto_bind=True)
        else:
            conn = ldap3.Connection(server, auto_bind=True)
        
        base_dn = ','.join([f'DC={x}' for x in domain.split('.')])
        
        # Chercher les utilisateurs
        conn.search(base_dn, '(objectClass=user)', attributes=['sAMAccountName', 'memberOf', 'userAccountControl', 'servicePrincipalName'])
        for entry in conn.entries:
            user_info = {
                'name': str(entry.sAMAccountName),
                'memberOf': [str(g) for g in entry.memberOf] if entry.memberOf else [],
                'has_spn': len(entry.servicePrincipalName) > 0 if entry.servicePrincipalName else False,
                'uac': str(entry.userAccountControl)
            }
            results['users'].append(user_info)
        
        # Chercher les groupes
        conn.search(base_dn, '(objectClass=group)', attributes=['cn', 'member'])
        for entry in conn.entries:
            results['groups'].append(str(entry.cn))
        
        # Chercher les computers
        conn.search(base_dn, '(objectClass=computer)', attributes=['cn', 'operatingSystem'])
        for entry in conn.entries:
            results['computers'].append({
                'name': str(entry.cn),
                'os': str(entry.operatingSystem) if entry.operatingSystem else 'Unknown'
            })
        
        conn.unbind()
    except Exception as e:
        console.print(f"[yellow][!] LDAP anonyme échoué: {e}[/yellow]")
    
    return results
