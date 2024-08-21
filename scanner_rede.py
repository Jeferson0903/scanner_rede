import nmap
import socket
import tkinter as tk
from tkinter import scrolledtext

# Função para obter o IP local e a sub-rede
def get_ip_and_subnet():
    hostname = socket.gethostname()
    ip_local = socket.gethostbyname(hostname)
    ip_network = ip_local.rsplit('.', 1)[0] + '.0/24'
    return ip_local, ip_network

# Função para escanear uma sub-rede específica
def scan_subnet(destino):
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=destino, arguments='-sn')
        hosts_ativos = nm.all_hosts()
        
        if hosts_ativos:
            results_text.insert(tk.END, 'Hosts Ativos Encontrados:\n')
            for host in hosts_ativos:
                host_state = nm[host].state()
                results_text.insert(tk.END, f'{host} está {host_state}\n')
        else:
            results_text.insert(tk.END, 'Nenhum host ativo encontrado na sub-rede.\n')

        if hosts_ativos:
            for host_ip in hosts_ativos:
                try:
                    nm.scan(hosts=host_ip, arguments='-p 1-1000')
                    if 'tcp' in nm[host_ip]:
                        results_text.insert(tk.END, f'Portas abertas no host {host_ip}:\n')
                        for port in nm[host_ip]['tcp']:
                            port_state = nm[host_ip]['tcp'][port]['state']
                            port_name = nm[host_ip]['tcp'][port].get('name', 'unknown')
                            results_text.insert(tk.END, f'    Porta {port} ({port_name}) está {port_state}\n')
                    else:
                        results_text.insert(tk.END, f'Nenhuma porta TCP detectada no host {host_ip}.\n')
                except Exception as e:
                    results_text.insert(tk.END, f'Erro ao escanear portas do host {host_ip}: {e}\n')
        
    except Exception as e:
        results_text.insert(tk.END, f'Erro ao escanear a sub-rede: {e}\n')

# Função para gerar sub-redes vizinhas
def generate_nearby_subnets(base_subnet):
    base_ip = base_subnet.rsplit('.', 2)[0]
    subnets = []
    for i in range(0, 256, 1):
        subnets.append(f"{base_ip}.{i}.0/24")
    return subnets

# Função para executar a varredura de rede e atualizar a interface
def scan_network():
    results_text.delete(1.0, tk.END)
    ip_local, ip_principal = get_ip_and_subnet()
    results_text.insert(tk.END, f'IP Local: {ip_local}\n')
    
    # Escanear a sub-rede principal
    results_text.insert(tk.END, f'Escaneando a sub-rede principal: {ip_principal}\n')
    scan_subnet(ip_principal)
    
    # Gerar e escanear sub-redes vizinhas
    nearby_subnets = generate_nearby_subnets(ip_principal)
    for subnet in nearby_subnets:
        results_text.insert(tk.END, f'Escaneando a sub-rede: {subnet}\n')
        scan_subnet(subnet)

window = tk.Tk()
window.title("Scanner de Rede")

scan_button = tk.Button(window, text="Iniciar Varredura", command=scan_network)
scan_button.pack(pady=10)

results_text = scrolledtext.ScrolledText(window, width=80, height=20)
results_text.pack(pady=10)

window.mainloop()
