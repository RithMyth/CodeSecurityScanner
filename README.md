# 🛡️ CodeSecurityScanner V2

Ein leistungsstarker, statischer Sicherheits-Scanner für Python-Projekte. Dieses Tool analysiert Quellcode auf Sicherheitslücken wie SQL-Injection, Remote Code Execution (RCE), hardcodierte Secrets und unsichere Konfigurationen.

## ✨ Features
- **AST-Analyse:** Erkennt gefährliche Funktionsaufrufe (`eval`, `os.system`) durch Struktur-Analyse, nicht nur Textsuche.
- **Regex-Detection:** Findet Secrets wie Slack-Tokens, AWS-Keys und Passwörter.
- **Smart Filtering:** Ignoriert Kommentare und gängige Fehlalarme.
- **Colorized Terminal:** Übersichtliche Ausgabe mit farblichen Schweregraden (Rot/Gelb).
- **Automated Reporting:** Erstellt einen detaillierten `SicherheitsReport.txt`.

## 🚀 Installation & Start
1. Repository klonen:
2. python3 SecurityScanner.py
   (zu prüfende Datei muss immer im selben Ordner liegen)
   
```bash

git clone
[https://github.com/RithMyth/CodeSecurityScanner.git]  (https://github.com/RithMyth/CodeSecurityScanner.git)
 cd CodeSecurityScanner
