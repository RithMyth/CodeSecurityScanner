# =================================================
# SECURITY SCANNER (FULL VERSION + COLORS + FIX)
# =================================================
import ast
import re
import os
from datetime import datetime

# ANSI Farben für das Terminal
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
GREEN = "\033[92m"
BOLD = "\033[1m"
RESET = "\033[0m"

# 1. VOLLSTÄNDIGE GEFAHRENLISTE 
gefahren = {
    # --- 1. CODE AUSFÜHRUNG (RCE) & MALWARE-TRICKS ---
    r"(eval|exec|compile)\s*\(": "KRITISCH: RCE Risiko! LÖSUNG: Nutze ast.literal_eval() für Daten oder Dictionary-Mapping.",
    r"os\.(system|popen|spawnl|spawnv)\s*\(": "HOCH: Systemaufruf! LÖSUNG: Nutze 'subprocess' Modul ohne shell=True.",
    r"subprocess\.(run|Popen|call|check_output)\s*\(.*shell\s*=\s*True": "HOCH: shell=True gefunden! LÖSUNG: Übergib Befehle als Liste: ['ls', '-l'].",
    r"__import__\s*\(\s*['\"]os['\"]\s*\)\.system": "KRITISCH: Obfuscation! LÖSUNG: Code sofort auf Backdoors prüfen.",
    r"getattr\s*\(\s*.*,\s*['\"].*['\"]\s*\)\s*\(": "HOCH: Dynamischer Aufruf! LÖSUNG: Whitelist erlaubter Funktionen erstellen.",
    r"eval\s*\(\s*base64\.": "KRITISCH: Payload-Verdacht! LÖSUNG: Daten manuell dekodieren und vor Ausführung prüfen.",
    r"chr\s*\(\s*\d+\s*\)": "INFO: Zeichen-Tarnung. LÖSUNG: Prüfen, ob 'eval' oder 'exec' buchstabiert wird.",

    # --- 2. SQL INJECTION ---
    r"\.execute\s*\(\s*f[\"']": "HOCH: SQLi durch f-String! LÖSUNG: Nutze Parameter-Binding: .execute('SELECT * FROM u WHERE id=?', (id,)).",
    r"\.execute\s*\(\s*['\"].*%.*['\"]\s*,\s*": "WARNUNG: SQLi durch %! LÖSUNG: Nutze das Parameter-System des DB-Treibers.",
    r"\.execute\s*\(\s*['\"].*\{\}.*['\"]\s*\.format": "HOCH: SQLi durch .format()! LÖSUNG: Variablen niemals direkt einbetten.",

    # --- 3. SECRETS, TOKENS & KEYS ---
    r"(password|passwd|secret|token|api_key|access_key|auth)\s*=\s*['\"][^'\"]{8,}['\"]": "KRITISCH: Hardcoded Secret! LÖSUNG: Nutze Umgebungsvariablen (.env) oder Key-Vaults.",
    r"AWS_(SECRET|ACCESS)_KEY\s*=\s*": "KRITISCH: AWS-Key! LÖSUNG: Nutze IAM Roles oder ~/.aws/credentials.",
    r"xox[bp]-[0-9]{12}": "KRITISCH: Slack-Token! LÖSUNG: Token sofort widerrufen (Revoke)!",
    r"ssh-rsa\s+[A-Za-z0-9+/]{100,}": "KRITISCH: SSH-Key! LÖSUNG: Private Keys aus Code entfernen.",

    # --- 4. DATENSICHERHEIT & DESERIALISIERUNG ---
    r"pickle\.(load|loads)\s*\(": "HOCH: Unsicheres Pickle! LÖSUNG: Nutze JSON oder hmac-Signierung.",
    r"marshal\.loads\s*\(": "HOCH: Unsicheres marshal! LÖSUNG: Nur für vertrauenswürdige interne Daten nutzen.",
    r"yaml\.(load|load_all)\s*\(\s*[^,]*\s*\)": "WARNUNG: Unsicheres YAML! LÖSUNG: Nutze yaml.safe_load().",
    r"base64\.b64decode\s*\(": "INFO: Base64 gefunden. LÖSUNG: Datenursprung prüfen (keine Verschlüsselung!).",

    # --- 5. NETZWERK & INFRASTRUKTUR ---
    r"verify\s*=\s*False": "WARNUNG: SSL deaktiviert! LÖSUNG: Setze verify=True (Schutz vor Man-in-the-Middle).",
    r"0\.0\.0\.0": "INFO: 0.0.0.0 Bindung. LÖSUNG: Nutze '127.0.0.1' oder spezifische Interface-IPs.",
    r"http://": "WARNUNG: Unverschlüsseltes HTTP! LÖSUNG: Nutze HTTPS.",
    r"ftp://|telnet://": "KRITISCH: Veraltetes Protokoll! LÖSUNG: Nutze SFTP oder SSH.",
    r"mongodb\+srv://": "KRITISCH: DB-String! LÖSUNG: Zugangsdaten in Vault speichern.",
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}": "INFO: Hardcoded IP! LÖSUNG: Nutze DNS-Namen oder Config-Files.",

    # --- 6. KRYPTOGRAPHIE ---
    r"hashlib\.(md5|sha1)\s*\(": "WARNUNG: Schwacher Hash! LÖSUNG: Nutze SHA256 oder Argon2/Bcrypt.",
    r"random\.(randint|random|choice)": "INFO: Vorhersehbarer Zufall. LÖSUNG: Nutze das 'secrets' Modul.",
    r"['\"]ECB['\"]": "HOCH: Unsicherer AES-Modus! LÖSUNG: Nutze AES-GCM.",

    # --- 7. DATEISYSTEM & WEB-LOGIK ---
    r"os\.chmod\s*\(.*(0o777|777|stat\.S_IRWXO)": "HOCH: Weltweite Rechte (777)! LÖSUNG: Nutze 0o600 oder 0o644.",
    r"tempfile\.mktemp\s*\(": "WARNUNG: mktemp() veraltet. LÖSUNG: Nutze tempfile.mkstemp().",
    r"DEBUG\s*=\s*True": "WARNUNG: Debug-Mode aktiv! LÖSUNG: Setze DEBUG = False im Live-Betrieb.",
    r"input\s*\(": "INFO: Input gefunden. LÖSUNG: Eingaben validieren (Länge/Inhalt)."
}

# 2. INITIALISIERUNG
pfad_wahl = input(f"{BOLD}Welchen Pfad willst du checken?: {RESET}")
dateien_gesamt = 0
gefahren_gesamt = 0
report_inhalt = []
blacklist = [".git", "__pycache__", "venv", ".idea", "node_modules"]

# Pfad-Fix für den Report: Speichert immer im Ordner des Skripts
skript_ordner = os.path.dirname(os.path.abspath(__file__))
report_pfad = os.path.join(skript_ordner, "SicherheitsReport.txt")

# 3. SCAN-LOGIK
if os.path.isdir(pfad_wahl):
    print(f"\n{CYAN}{BOLD}--- Starte Profi-Analyse für: {pfad_wahl} ---{RESET}")

    for root, dirs, files in os.walk(pfad_wahl):
        dirs[:] = [d for d in dirs if d not in blacklist]
        
        for datei in files:
            if datei == "SecurityScanner.py": continue
            if datei.endswith(".py"):
                dateien_gesamt += 1
                voller_pfad = os.path.join(root, datei)
                
                try:
                    with open(voller_pfad, "r", encoding="utf-8") as f:
                        code_inhalt = f.read()
                        zeilen = code_inhalt.splitlines()

                        # --- AST-ANALYSE ---
                        try:
                            baum = ast.parse(code_inhalt)
                            for knoten in ast.walk(baum):
                                if isinstance(knoten, ast.Call):
                                    f_full_name = ""
                                    if isinstance(knoten.func, ast.Name): f_full_name = knoten.func.id
                                    elif isinstance(knoten.func, ast.Attribute):
                                        f_full_name = f"{knoten.func.value.id}.{knoten.func.attr}" if isinstance(knoten.func.value, ast.Name) else knoten.func.attr
                                    
                                    if f_full_name:
                                        test_call = f"{f_full_name}("
                                        for muster, warnung in gefahren.items():
                                            if r"\(" in muster and re.search(muster, test_call):
                                                gefahren_gesamt += 1
                                                # Farbe basierend auf Schweregrad
                                                farbe = RED if any(x in warnung for x in ["KRITISCH", "HOCH"]) else YELLOW
                                                fund_msg = f"[!] AST-Treffer in {datei} (Zeile {knoten.lineno}):\n   -> Gefahr: {f_full_name}()\n   -> {warnung}"
                                                print(f"{farbe}{fund_msg}{RESET}")
                                                report_inhalt.append(fund_msg)
                                                break
                        except SyntaxError: pass

                        # --- REGEX-ANALYSE ---
                        for zeile_nr, inhalt in enumerate(zeilen, start=1):
                            if inhalt.strip().startswith("#"): continue
                            for muster, warnung in gefahren.items():
                                if r"\(" not in muster and re.search(muster, inhalt):
                                    gefahren_gesamt += 1
                                    farbe = RED if any(x in warnung for x in ["KRITISCH", "HOCH"]) else YELLOW
                                    fund_msg = f"[!] REGEX-Treffer in {datei} (Zeile {zeile_nr}):\n    -> {warnung}\n    -> Code: {inhalt.strip()}"
                                    print(f"{farbe}{fund_msg}{RESET}")
                                    report_inhalt.append(fund_msg)

                except Exception as e:
                    print(f"{RED}Fehler in {datei}: {e}{RESET}")

    # 4. REPORT SPEICHERN
    zeitstempel = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(report_pfad, "w", encoding="utf-8") as report_file:
            report_file.write("===========================================\n")
            report_file.write("            SECURITY SCAN REPORT           \n")
            report_file.write(f"       Zeitpunkt: {zeitstempel}\n")
            report_file.write("===========================================\n\n")
            report_file.write(f"Gescannte Dateien: {dateien_gesamt}\n")
            report_file.write(f"Gefundene Risiken: {gefahren_gesamt}\n\n")
            report_file.write("DETAILS:\n" + "-" * 50 + "\n")
            for fund in report_inhalt:
                report_file.write(fund + "\n" + "-" * 50 + "\n")
        
        print(f"\n{GREEN}{BOLD}[OK] Scan abgeschlossen. {gefahren_gesamt} Risiken gefunden.{RESET}")
        print(f"{CYAN}Bericht wurde hier gespeichert: {report_pfad}{RESET}")

    except Exception as e:
        print(f"{RED}Fehler beim Speichern: {e}{RESET}")
else:
    print(f"{RED}Pfad nicht gefunden.{RESET}")
