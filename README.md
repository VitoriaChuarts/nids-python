# NIDS - Sistema de Detecção de Intrusão de Rede

Sistema de detecção de intrusão em nível de pacote, construído em Python com Scapy, capaz de identificar port scans e ataques de SYN flood analisando tráfego de rede em tempo real.

## Como funciona

1. Captura pacotes diretamente da interface de rede usando Scapy
2. Analisa o cabeçalho TCP/IP de cada pacote (IP de origem, porta de destino, flags)
3. Detecta port scan: quando um mesmo IP tenta acessar 10 ou mais portas diferentes em uma janela curta de tempo
4. Detecta SYN flood: quando um mesmo IP envia um volume anormal de pacotes SYN
5. Gera alertas em tempo real e registra em log

## Tecnologias usadas

- Python 3
- Scapy (captura e análise de pacotes em nível de rede)
- Nmap e Hping3 (usados para testar as detecções)

## Como executar

```
sudo python3 nids.py
```

(requer privilégios de administrador para capturar pacotes de rede)

## Autora

Vitória CHuarts
