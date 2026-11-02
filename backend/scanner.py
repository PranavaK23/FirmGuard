"""Explainable rules. Source values and source lines are never returned."""
import re
from pathlib import PurePosixPath
PASSWORD_KEYS = {"password", "passwd", "pwd", "admin_password", "root_password"}
WIFI_KEYS = {"wifi_password", "wifi_pass", "wpa_passphrase", "psk"}
API_KEYS = {"api_key", "apikey", "api_token", "access_token", "auth_token", "secret_key", "client_secret"}
KEYS = "|".join(sorted(PASSWORD_KEYS | WIFI_KEYS | API_KEYS, key=len, reverse=True))
PATTERN = re.compile(rf"(?<![\w-])(?P<quote>[\"']?)(?P<key>{KEYS})(?P=quote)"
    r"\s*[=:]\s*(?P<value>\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;#}\]]+)", re.I)

def finding(rule, title, path, severity, explanation, remediation, line=None, **extra):
    return {"rule_id": rule, "type": title, "filename": path, "line": line,
        "severity": severity, "explanation": explanation, "remediation": remediation, **extra}

def scan_credentials(text, filename):
    found = []
    for number, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith(("#", ";", "//")): continue
        for match in PATTERN.finditer(line):
            key, value = match["key"].lower(), match["value"].strip("\"'").strip()
            if not value or value.lower() in {"null", "none", "redacted", "********"} or value.startswith(("${", "{{")): continue
            title = "Hardcoded Wi-Fi password" if key in WIFI_KEYS else "Hardcoded API key / token" if key in API_KEYS else "Hardcoded password"
            found.append(finding("CRED-001", title, filename, "High", "A literal credential assignment was detected. Its value is hidden.",
                "Remove embedded secrets, rotate exposed credentials and use protected provisioning.", number,
                key=key, masked_value="********", category="Credentials"))
        if re.search(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----", line):
            found.append(finding("CRED-002", "Embedded private key", filename, "High", "A private-key header is present; key material is withheld.",
                "Remove the key and replace affected device credentials.", number, category="Credentials"))
    return found

CONFIG_RULES = [
 ("sshd_config", r"^\s*PermitRootLogin\s+yes\b", "CONF-SSH-ROOT", "SSH root login enabled", "High", "Disable direct root login."),
 ("sshd_config", r"^\s*PermitEmptyPasswords\s+yes\b", "CONF-SSH-EMPTY", "SSH empty passwords allowed", "High", "Set PermitEmptyPasswords to no."),
 ("sshd_config", r"^\s*PasswordAuthentication\s+yes\b", "CONF-SSH-PASSWORD", "SSH password authentication enabled", "Medium", "Prefer provisioned SSH keys where feasible."),
 ("sshd_config", r"^\s*Protocol\s+1(?:\s|,|$)", "CONF-SSH-V1", "SSH protocol 1 enabled", "High", "Use SSH protocol 2."),
 ("*", r"^\s*(?:telnet|telnet_enabled)\s*[=:]\s*(?:1|yes|true|on|enabled)\b", "CONF-TELNET", "Telnet enabled", "High", "Disable Telnet and use SSH."),
 ("*", r"^\s*(?:ssl_verify|tls_verify|verify_certificate)\s*[=:]\s*(?:0|false|no|off)\b", "CONF-TLS", "Certificate verification disabled", "High", "Enable certificate and hostname verification."),
 ("*", r"^\s*(?:debug|debug_enabled)\s*[=:]\s*(?:1|true|yes|on)\b", "CONF-DEBUG", "Debug mode enabled", "Medium", "Disable debug mode in released firmware."),
 ("*", r"^\s*(?:rocommunity|rwcommunity)\s+(?:public|private)\b", "CONF-SNMP", "Default SNMP community", "High", "Use SNMPv3 and restrict access."),
 ("vsftpd.conf", r"^\s*anonymous_enable\s*=\s*YES\b", "CONF-FTP", "Anonymous FTP enabled", "Medium", "Disable anonymous access unless required."),
 ("*", r"^\s*net\.ipv4\.ip_forward\s*=\s*1\b", "CONF-FORWARD", "IPv4 forwarding enabled", "Info", "Confirm forwarding is intended and protected by firewall rules."),
]

def scan_configuration(text, filename, mode=0):
    found, conditional = [], False
    base = PurePosixPath(filename).name.lower()
    for number, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith(("#", ";", "//")): continue
        if base == "sshd_config" and re.match(r"\s*Match\s", line, re.I): conditional = True
        for target, pattern, rule, title, severity, remedy in CONFIG_RULES:
            if (target == "*" or target == base) and re.search(pattern, line, re.I):
                found.append(finding(rule, title, filename, severity,
                    "An explicit setting matches this rule. Includes, defaults and runtime overrides are not resolved." +
                    (" This setting is in a conditional Match block." if conditional else ""), remedy, number, category="Configuration"))
        if base in {"passwd", "shadow"}:
            fields = line.split(":")
            if len(fields) >= 2 and fields[0] and fields[1] == "":
                found.append(finding("CONF-ACCOUNT-EMPTY", "Account with empty password field", filename, "High",
                    "An account record has an empty password field. Account names are withheld.", "Lock unused accounts and require authentication.", number, category="Configuration"))
            elif base == "passwd" and len(fields) >= 2 and fields[1].startswith(("$1$", "$5$", "$6$", "$y$")):
                found.append(finding("CONF-PASSWD-HASH", "Password hash in passwd file", filename, "High",
                    "A password hash appears in passwd.", "Store hashes in a restricted shadow file.", number, category="Configuration"))
    if mode & 0o002:
        found.append(finding("CONF-WRITABLE", "World-writable file", filename, "Medium", "Archive permissions allow writes by other users.", "Remove world-write permission.", category="Configuration"))
    if mode & 0o6000:
        found.append(finding("CONF-PRIVILEGED", "Set-user-ID or set-group-ID file", filename, "Medium", "Archive permissions include a privilege-changing bit.", "Review and remove unnecessary privilege bits.", category="Configuration"))
    return found

def preliminary_risk(findings):
    return "Review needed" if findings else "No patterns detected"
