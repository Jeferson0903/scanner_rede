import nmap
import socket
import tkinter as tk
from tkinter import scrolledtext
import threading
import scapy.all as scapy

# Função para obter o IP local e a sub-rede principal
def get_ip_and_subnet():
    hostname = socket.gethostname()
    ip_local = socket.gethostbyname(hostname)
    ip_network = ip_local.rsplit('.', 1)[0] + '.0/24'
    return ip_local, ip_network

# Função para obter o nome do host (hostname) a partir de um IP
def get_hostname(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        hostname = "Hostname desconhecido"
    return hostname

# Função para escanear uma sub-rede específica
def scan_subnet(destino):
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=destino, arguments='-sn -T4 --max-retries 0')
        hosts_ativos = nm.all_hosts()
        
        if hosts_ativos:
            results_text.insert(tk.END, 'Hosts Ativos Encontrados:\n')
            for host in hosts_ativos:
                host_state = nm[host].state()
                hostname = get_hostname(host)
                results_text.insert(tk.END, f'{host} ({hostname}) está {host_state}\n')
                # Utilizar threads para escanear portas
                threading.Thread(target=scan_ports, args=(host,)).start()
        else:
            results_text.insert(tk.END, 'Nenhum host ativo encontrado na sub-rede.\n')

    except Exception as e:
        results_text.insert(tk.END, f'Erro ao escanear a sub-rede: {e}\n')

# Função para escanear portas de um host específico
def scan_ports(host_ip):
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=host_ip, arguments='-p 22,80,443 -T4 --max-retries 0')
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

# Função para escanear a sub-rede com ARP usando Scapy
def scan_subnet_with_arp(subnet):
    results_text.insert(tk.END, f'Escaneando com ARP a sub-rede: {subnet}\n')
    arp_request = scapy.ARP(pdst=subnet)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    if answered_list:
        results_text.insert(tk.END, 'Dispositivos Encontrados:\n')
        for element in answered_list:
            results_text.insert(tk.END, f'{element[1].psrc} ({element[1].hwsrc})\n')
    else:
        results_text.insert(tk.END, 'Nenhum dispositivo encontrado na sub-rede com ARP.\n')

# Função para descobrir sub-redes adicionais
def discover_additional_subnets():
    results_text.insert(tk.END, 'Tentando descobrir sub-redes adicionais...\n')
    # Limite o intervalo de verificação para sub-redes comuns
    for i in range(1, 10):  # Ajuste o intervalo conforme necessário
        subnet = f'192.168.{i}.0/24'
        scan_subnet(subnet)

# Função para executar a varredura de rede e atualizar a interface
def scan_network():
    results_text.delete(1.0, tk.END)
    ip_local, ip_principal = get_ip_and_subnet()
    results_text.insert(tk.END, f'IP Local: {ip_local}\n')
    
    # Escanear a sub-rede principal
    results_text.insert(tk.END, f'Escaneando a sub-rede principal: {ip_principal}\n')
    scan_subnet(ip_principal)
    
    # Descobrir sub-redes adicionais
    discover_additional_subnets()

    # Escanear sub-rede do roteador secundário
    results_text.insert(tk.END, 'Escaneando a sub-rede do roteador secundário: 192.168.1.0/24\n')
    scan_subnet('192.168.1.0/24')

    # Adicionar escaneamento ARP
    scan_subnet_with_arp(ip_principal)
    scan_subnet_with_arp('192.168.1.0/24')

# Configuração da interface gráfica
window = tk.Tk()
window.title("Scanner de Rede")

scan_button = tk.Button(window, text="Iniciar Varredura", command=scan_network)
scan_button.pack(pady=10)

results_text = scrolledtext.ScrolledText(window, width=80, height=20)
results_text.pack(pady=10)

window.mainloop()
