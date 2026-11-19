import os
from datetime import datetime, timezone

import requests

SIEM_URL = os.environ.get("SIEM_URL", "http://localhost:8080/api/alerts")
API_KEY = os.environ.get("SIEM_API_KEY", "")


def enviar_alerta(ip, tipo_evento, severidade, detalhes):
    alerta = {
        "source": "nids",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "srcIp": ip,
        "eventType": tipo_evento,
        "severity": severidade,
        "details": detalhes,
    }
    try:
        requests.post(SIEM_URL, json=alerta,
                      headers={"X-API-Key": API_KEY}, timeout=2)
    except requests.RequestException:
        pass
