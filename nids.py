from scapy.all import sniff, IP, TCP
from collections import defaultdict
from datetime import datetime
import time

contagem_portas = defaultdict(set)
contagem_syn = defaultdict(int)
ultimo_alerta = {}
ultimo_alerta_flood = {}

LIMITE_PORTAS = 10
LIMITE_SYN_FLOOD = 50
JANELA_SEGUNDOS = 10

def processar_pacote(pacote):
    if pacote.haslayer(IP) and pacote.haslayer(TCP):
        ip_origem = pacote[IP].src
        porta_destino = pacote[TCP].dport
        flags = pacote[TCP].flags

        if flags == "S":
            contagem_portas[ip_origem].add(porta_destino)
            contagem_syn[ip_origem] += 1

            # Verificação de Port Scan
            if len(contagem_portas[ip_origem]) >= LIMITE_PORTAS:
                agora = time.time()
                if ip_origem not in ultimo_alerta or (agora - ultimo_alerta[ip_origem]) > JANELA_SEGUNDOS:
                    horario = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    portas = sorted(contagem_portas[ip_origem])
                    alerta = f"{horario} | POSSIVEL PORT SCAN de {ip_origem} -> {len(portas)} portas: {portas}\n"
                    print(alerta)
                    with open("nids.log", "a", encoding="utf-8") as log:
                        log.write(alerta)
                    ultimo_alerta[ip_origem] = agora
                    contagem_portas[ip_origem].clear()

            # Verificação de SYN Flood
            if contagem_syn[ip_origem] >= LIMITE_SYN_FLOOD:
                agora = time.time()
                if ip_origem not in ultimo_alerta_flood or (agora - ultimo_alerta_flood[ip_origem]) > JANELA_SEGUNDOS:
                    horario = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    alerta = f"{horario} | POSSIVEL SYN FLOOD de {ip_origem} -> {contagem_syn[ip_origem]} pacotes SYN\n"
                    print(alerta)
                    with open("nids.log", "a", encoding="utf-8") as log:
                        log.write(alerta)
                    ultimo_alerta_flood[ip_origem] = agora
                    contagem_syn[ip_origem] = 0


print("[+] NIDS iniciado. Monitorando interface lo...")

sniff(
    iface="lo",
    filter="tcp",
    prn=processar_pacote,
    store=False
)
