# 🛡️ CodeSecurityScanner 

Ein leistungsstarker, statischer Sicherheits-Scanner (SAST) für Python-Projekte. Das Tool analysiert Quellcode und Ordnerstrukturen auf kritische Schwachstellen wie Remote Code Execution (RCE), SQL-Injection, hardcodierte Secrets und unbewusste Fehlkonfigurationen.

---

## ✨ Features & Highlights

* **Duale Analyse-Engine:**
  * **AST-Analyse (Abstract Syntax Tree):** Erkennt gefährliche Funktionsaufrufe (`eval`, `exec`, `os.system`, `subprocess`) durch semantische Code-Struktur-Analyse.
  * **Regex-Pattern-Matching:** Identifiziert hardcodierte Secrets (AWS Keys, Slack-Tokens, API-Keys, SSH-Keys, Passwörter) und unsichere Muster.
* **Flexibler Target-Support:** Scannt wahlweise eine **einzelne Datei** oder **ganze Ordnerstrukturen** (inkl. automatischer Ignorierung von `.git`, `venv`, `__pycache__` etc.).
* **Smart CLI & Interaktivität:** Nimmt Pfade direkt als Argument an (`python3 SecurityScanner.py <pfad>`) oder fragt interaktiv nach, wenn kein Pfad angegeben wird.
* **Colorized Terminal Output:** Übersichtliche Konsolenausgabe mit farblicher Abstufung nach Schweregrad (**KRITISCH**, **HOCH**, **WARNUNG**, **INFO**).
* **Automated Reporting:** Erstellt bei jedem Durchlauf automatisch einen Zeitstempel-basierten Auditreport (`SicherheitsReport.txt`) im Skriptverzeichnis.

---

## 🚀 Installation & Start

1. **Repository klonen:**
   ```bash
   git clone [https://github.com/RithMyth/CodeSecurityScanner.git](https://github.com/RithMyth/CodeSecurityScanner.git)
   cd CodeSecurityScanner
