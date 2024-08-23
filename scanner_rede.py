import nmap
import socket
import tkinter as tk
from tkinter import scrolledtext
from tkinter import ttk
import threading
import scapy.all as scapy
import warnings

# Suprimir todos os avisos de depreciação
warnings.filterwarnings("ignore", category=DeprecationWarning)

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
        # Aumente o tempo de espera e número de tentativas para uma detecção mais robusta
        nm.scan(hosts=destino, arguments='-sn -T4 --min-parallelism 10 --max-retries 2')
        hosts_ativos = nm.all_hosts()

        if hosts_ativos:
            results_text.insert(tk.END, '\nHosts Ativos Encontrados:\n', 'header')
            for host in hosts_ativos:
                host_state = nm[host].state()
                hostname = get_hostname(host)
                results_text.insert(tk.END, f'{host} ({hostname}) está {host_state}\n', 'host')
                # Utilizar threads para escanear portas de forma otimizada
                threading.Thread(target=scan_ports, args=(host,)).start()
        else:
            results_text.insert(tk.END, 'Nenhum host ativo encontrado na sub-rede.\n', 'info')

    except Exception as e:
        results_text.insert(tk.END, f'Erro ao escanear a sub-rede: {e}\n', 'error')

    # Atualizar a barra de progresso após escanear a sub-rede
    update_progress(30)  # Ajuste o valor conforme necessário

# Função para escanear portas de um host específico
def scan_ports(host_ip):
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=host_ip, arguments='-p 22,80,443 -T4 --min-parallelism 10 --max-retries 2')
        if 'tcp' in nm[host_ip]:
            results_text.insert(tk.END, f'\nPortas abertas no host {host_ip}:\n', 'header')
            for port in nm[host_ip]['tcp']:
                port_state = nm[host_ip]['tcp'][port]['state']
                port_name = nm[host_ip]['tcp'][port].get('name', 'unknown')
                results_text.insert(tk.END, f'    Porta {port} ({port_name}) está {port_state}\n', 'port')
        else:
            results_text.insert(tk.END, f'Nenhuma porta TCP detectada no host {host_ip}.\n', 'info')
    except Exception as e:
        results_text.insert(tk.END, f'Erro ao escanear portas do host {host_ip}: {e}\n', 'error')

    # Atualizar a barra de progresso após escanear as portas
    update_progress(60)  # Ajuste o valor conforme necessário

# Função para escanear a sub-rede com ARP usando Scapy
def scan_subnet_with_arp(subnet):
    results_text.insert(tk.END, f'\nEscaneando com ARP a sub-rede: {subnet}\n', 'header')
    arp_request = scapy.ARP(pdst=subnet)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)[0]  # Aumente o timeout se necessário

    if answered_list:
        results_text.insert(tk.END, 'Dispositivos Encontrados:\n', 'header')
        for element in answered_list:
            results_text.insert(tk.END, f'{element[1].psrc} ({element[1].hwsrc})\n', 'arp')
    else:
        results_text.insert(tk.END, 'Nenhum dispositivo encontrado na sub-rede com ARP.\n', 'info')

    # Atualizar a barra de progresso após escanear com ARP
    update_progress(80)  # Ajuste o valor conforme necessário

# Função para descobrir sub-redes adicionais
def discover_additional_subnets():
    results_text.insert(tk.END, '\nTentando descobrir sub-redes adicionais...\n', 'info')
    # Limite o intervalo de verificação para sub-redes comuns
    for i in range(1, 10):  # Ajuste o intervalo conforme necessário
        subnet = f'192.168.{i}.0/24'
        scan_subnet(subnet)

    # Atualizar a barra de progresso após descobrir sub-redes adicionais
    update_progress(50)  # Ajuste o valor conforme necessário

# Função para executar a varredura de rede e atualizar a interface
def scan_network():
    results_text.delete(1.0, tk.END)
    ip_local, ip_principal = get_ip_and_subnet()
    results_text.insert(tk.END, f'IP Local: {ip_local}\n', 'info')

    # Escanear a sub-rede principal
    results_text.insert(tk.END, f'\nEscaneando a sub-rede principal: {ip_principal}\n', 'info')
    scan_subnet(ip_principal)
    
    # Descobrir sub-redes adicionais
    discover_additional_subnets()

    # Escanear sub-rede do roteador secundário
    results_text.insert(tk.END, '\nEscaneando a sub-rede do roteador secundário: 192.168.1.0/24\n', 'info')
    scan_subnet('192.168.1.0/24')

    # Adicionar escaneamento ARP
    scan_subnet_with_arp(ip_principal)
    scan_subnet_with_arp('192.168.1.0/24')

    # Finalizar e atualizar a barra de progresso
    update_progress(100)  # Ajuste o valor conforme necessário

# Configuração da interface gráfica
window = tk.Tk()
window.title("Scanner de Rede")

# Frame para os componentes da interface
frame_top = tk.Frame(window, padx=10, pady=10)
frame_top.pack(fill=tk.X)

# Botão de iniciar varredura
scan_button = tk.Button(frame_top, text="Iniciar Varredura", command=scan_network, bg='#20b2aa', fg='white', font=('Helvetica', 12, 'bold'))
scan_button.pack(pady=5)

# Barra de progresso
progress = tk.DoubleVar()
progress_bar = ttk.Progressbar(frame_top, variable=progress, maximum=100, length=200, mode='determinate', style='TProgressbar')
progress_bar.pack(pady=5)

# Frame para o texto dos resultados
frame_bottom = tk.Frame(window, padx=10, pady=10)
frame_bottom.pack(fill=tk.BOTH, expand=True)

# Texto dos resultados
results_text = scrolledtext.ScrolledText(frame_bottom, width=80, height=20, wrap=tk.WORD, font=('Courier New', 10))
results_text.pack(expand=True, fill=tk.BOTH)

# Estilo da barra de progresso
style = ttk.Style()
style.configure('TProgressbar', thickness=20, troughcolor='#20b2aa', background='#87cefa', bordercolor='#f0f8ff')

# Configuração das tags de cores no texto
results_text.tag_configure('header', foreground='#003366', font=('Courier New', 12, 'bold'))
results_text.tag_configure('host', foreground='#006600', font=('Courier New', 10))
results_text.tag_configure('port', foreground='#0033cc', font=('Courier New', 10))
results_text.tag_configure('arp', foreground='#cc6600', font=('Courier New', 10))
results_text.tag_configure('info', foreground='#111111', font=('Courier New', 10))
results_text.tag_configure('error', foreground='#ff0000', font=('Courier New', 10))

# Função para atualizar a barra de progresso
def update_progress(value):
    progress.set(value)
    window.update_idletasks()

window.mainloop()
