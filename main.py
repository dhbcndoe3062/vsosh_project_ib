import platform
import subprocess
import re
import sys
from datetime import datetime

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def print_header():
    print(f"{Colors.HEADER}{'='*45}")
    print("   ОФФЛАЙН-УТИЛИТА ПРОВЕРКИ Wi-Fi")
    print("   Оценка безопасности сети")
    print('='*45 + Colors.ENDC)

def get_wifi_info_windows():
    try:
        output = subprocess.check_output(
            "netsh wlan show interfaces", shell=True, encoding='cp866', errors='ignore'
        )
    except:
        return None, "Ошибка получения данных (Windows)"
    
    ssid = re.search(r"SSID\s+:\s*(.+)", output)
    auth = re.search(r"Аутентификация\s+:\s*(.+)|Authentication\s+:\s*(.+)", output)
    
    ssid = ssid.group(1).strip() if ssid else "Не подключено"
    auth = (auth.group(1) or auth.group(2)).strip() if auth else "Неизвестно"
    
    return {"ssid": ssid, "auth": auth}, None

def get_wifi_info_linux():
    try:
        output = subprocess.check_output(["nmcli", "-t", "-f", "ACTIVE,SSID,SECURITY", "device", "wifi"], encoding='utf-8')
        for line in output.splitlines():
            if line.startswith("yes:"):
                parts = line.split(":")
                ssid = parts[1] if len(parts) > 1 else "Неизвестно"
                security = parts[2] if len(parts) > 2 else "Open"
                return {"ssid": ssid, "auth": security}, None
    except:
        pass
    return None, "nmcli не найден или ошибка"

def assess_security(info):
    risk_score = 0
    problems = []
    mitre = []
    recommendations = []

    auth = info["auth"].upper()

    if "OPEN" in auth or auth == "NONE":
        risk_score += 4
        problems.append("Открытая сеть — любой может подключиться")
        mitre.append("Initial Access (TA0001)")
        recommendations.append("Включите шифрование WPA3 (минимум WPA2)")
    elif "WEP" in auth:
        risk_score += 4
        problems.append("WEP — устаревший и взламываемый протокол")
        mitre.append("Initial Access (TA0001)")
        recommendations.append("Перейдите на WPA2/WPA3")
    elif "WPA" in auth and "WPA2" not in auth and "WPA3" not in auth:
        risk_score += 2
        problems.append("WPA — устаревший протокол")
        recommendations.append("Перейдите на WPA3 или хотя бы WPA2")
    elif "WPA2" in auth:
        risk_score += 1

    wps_input = input(f"{Colors.OKBLUE}WPS включён на роутере? (yes/no, по умолчанию no): {Colors.ENDC}").strip().lower()
    wps_enabled = wps_input == "yes" or wps_input == "y"
    if wps_enabled:
        risk_score += 2
        problems.append("Включённый WPS — уязвим к подбору PIN")
        mitre.append("Credential Access (TA0006)")
        recommendations.append("Отключите WPS в настройках роутера")

    while True:
        try:
            pwd_len = input(f"{Colors.OKBLUE}Введите длину пароля Wi-Fi (число): {Colors.ENDC}").strip()
            pwd_len = int(pwd_len)
            break
        except:
            print(f"{Colors.FAIL}Введите корректное число!{Colors.ENDC}")
    
    if pwd_len < 8:
        risk_score += 3
        problems.append(f"Слишком короткий пароль ({pwd_len} символов)")
        mitre.append("Credential Access (TA0006)")
        recommendations.append("Используйте пароль минимум 12 символов")
    elif pwd_len < 12:
        risk_score += 1
        recommendations.append("Рекомендуется пароль 12+ символов")

    guest = input(f"{Colors.OKBLUE}Есть ли гостевые/открытые сети с похожим именем? (yes/no): {Colors.ENDC}").strip().lower()
    if guest in ["yes", "y"]:
        risk_score += 1
        problems.append("Обнаружены гостевые или открытые сети рядом")
        recommendations.append("Защитите или удалите гостевые сети")

    if risk_score >= 6:
        level = f"{Colors.FAIL}ВЫСОКИЙ{Colors.ENDC}"
    elif risk_score >= 3:
        level = f"{Colors.WARNING}СРЕДНИЙ{Colors.ENDC}"
    else:
        level = f"{Colors.OKGREEN}НИЗКИЙ{Colors.ENDC}"

    return {
        "level": level,
        "score": risk_score,
        "problems": problems,
        "mitre": mitre,
        "recommendations": recommendations
    }

def print_report(info, assessment):
    print(f"\n{Colors.BOLD}Текущая сеть (SSID):{Colors.ENDC} {info['ssid']}")
    print(f"{Colors.BOLD}Тип шифрования:{Colors.ENDC} {info['auth']}\n")
    print(f"{Colors.BOLD}Уровень риска: {assessment['level']}{Colors.ENDC}\n")

    if assessment["problems"]:
        print(f"{Colors.FAIL}Выявленные проблемы:{Colors.ENDC}")
        for p in assessment["problems"]:
            print(f"• {p}")
        print()
    else:
        print(f"{Colors.OKGREEN}Проблемы не выявлены. Отличная защита!{Colors.ENDC}\n")

    if assessment["mitre"]:
        print(f"{Colors.WARNING}Связанные тактики MITRE ATT&CK:{Colors.ENDC}")
        print(" • " + "\n • ".join(set(assessment["mitre"])) + "\n")

    print(f"{Colors.OKBLUE}Рекомендации:{Colors.ENDC}")
    for r in set(assessment["recommendations"]):
        print(f"   → {r}")
    print(f"\n{Colors.BOLD}Проверка завершена {datetime.now().strftime('%d.%m.%Y %H:%M')}{Colors.ENDC}\n")

def main():
    print_header()
    
    os_name = platform.system()
    if os_name == "Windows":
        info, error = get_wifi_info_windows()
    elif os_name == "Linux":
        info, error = get_wifi_info_linux()
    else:
        print(f"{Colors.FAIL}Поддерживаются только Windows и Linux{Colors.ENDC}")
        sys.exit(1)
    
    if error:
        print(f"{Colors.FAIL}{error}{Colors.ENDC}")
        return
    
    assessment = assess_security(info)
    print_report(info, assessment)

if __name__ == "__main__":
    main()
