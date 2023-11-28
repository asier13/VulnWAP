import requests
import socket
import threading
import time
import re
import json
from datetime import datetime
from requests import get, exceptions
from bs4 import BeautifulSoup as bs
from concurrent.futures import ThreadPoolExecutor, as_completed
from vectors import vectors


s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"

def get_all_forms(url):
    #Obtener todos los formularios del contenido HTML de una `url`.
    soup = bs(s.get(url).content, "html.parser")
    return soup.find_all("form")

def get_form_details(form):
    #Extrae toda la información útil de un `form` HTML
    details = {}

    # Sacar la accion del form (target url)
    try:
        action = form.attrs.get("action").lower()
    except:
        action = None

    # Sacar el metodo del form (POST, GET, etc.)
    method = form.attrs.get("method", "get").lower()

    # Sacar todos los inputs como name o tipo
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({"type": input_type, "name": input_name, "value": input_value})

    # Guardarlo todo en el diccionario
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def is_vulnerable_sqli(response):
    sqli_patterns = [
        r"you have an error in your sql syntax",
        r"warning: mysql",
        r"unclosed quotation mark after the character string",
        r"quoted string not properly terminated",
        r"sql syntax.*mysql",
        r"postgresql.*error",
        r"oracle.*error",
        r"microsoft sql server.*error",
        r"syntax error.*sql",
        r"sqlite.*error",
        r"constraint failed",
        r"invalid input syntax for type",
        r"undefined function.*sql",
        r"invalid query",
        r"command denied to user",
        r"ora-[0-9]+",
        r"psql:",
        r"plsql:",
        r"sql command not properly ended",
    ]
    for pattern in sqli_patterns:
        if re.search(pattern, response.text, re.IGNORECASE):
            return True
    return False

def test_sqli_payload(target_url, payload, counter):
    try:
        response = requests.get(target_url, params={"param": payload})
        if is_vulnerable_sqli(response):
            return payload, True
    except Exception as e:
        print(f"Error al probar el payload #{counter}: {e}")
    return payload, False

def check_sqli(target_url, payload_file="combined_payloads.txt", max_workers=50):
    vulnerable_payloads = []

    with open(payload_file, "r", encoding="utf-16") as file:
        payloads = [line.strip() for line in file if line.strip()]

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_payload = {executor.submit(test_sqli_payload, target_url, payload, counter): payload for counter, payload in enumerate(payloads, start=1)}
        for future in as_completed(future_to_payload):
            payload, is_vulnerable = future.result()
            if is_vulnerable:
                print(f"[+] Vulnerabilidad SQLi detectada con payload: {payload}")
                vulnerable_payloads.append(payload)

    return "Vulnerabilidad SQLi detectada" if vulnerable_payloads else "No se detectaron vulnerabilidades SQLi", vulnerable_payloads

def ddos_request(url):
    try:
        response = get(url, timeout=5)  # timeout de 5 segundos
        return response.status_code == 200
    except exceptions.RequestException:
        return False

def check_ddos(target_url):
    num_requests = 5000
    failed_requests = 0
    
    with ThreadPoolExecutor(max_workers=800) as executor:
        results = list(executor.map(ddos_request, [target_url] * num_requests))
    
    failed_requests = results.count(False)
    
    if failed_requests > (num_requests / 2):  # Si más del 50% de las solicitudes fallaron
        details = {
            "num_requests": num_requests,
            "failed_requests": failed_requests
        }
        return ("El sitio puede ser vulnerable a ataques DDoS.", details)
    else:
        return "El sitio parece ser resistente a ataques DDoS.", None


def load_xss_payloads(file_path):
    with open(file_path, 'r') as file:
        data = json.load(file)
    return [item['payload'] for item in data if 'payload' in item]

def test_payload(target_url, payload, browser_info, counter):
    try:
        full_url = f"{target_url}{payload}"
        response = requests.get(full_url)
        if payload in response.text:
            return payload, browser_info, True
    except Exception as e:
        print(f"Error al probar el payload #{counter}: {e}")
    return payload, browser_info, False

def check_xss(target_url):
    vulnerable_payloads = []

    with ThreadPoolExecutor(max_workers=50) as executor:
        future_to_payload = {executor.submit(test_payload, target_url, vector['payload'], vector.get('browser', 'Desconocido'), counter): vector for counter, vector in enumerate(vectors, start=1)}
        for future in as_completed(future_to_payload):
            payload, browser_info, is_vulnerable = future.result()
            if is_vulnerable:
                print(f"Payload vulnerable detectado: {payload} (Navegador: {browser_info})")
                vulnerable_payloads.append((payload, browser_info))

    return "Vulnerabilidad XSS detectada" if vulnerable_payloads else "No se detectaron vulnerabilidades XSS", vulnerable_payloads

def scan_port(target_ip, port, open_ports, interesting_ports, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    result = s.connect_ex((target_ip, port))
    if result == 0:
        if port in interesting_ports:
            open_ports[port] = interesting_ports[port]
        else:
            open_ports[port] = "Puerto no estandar"
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
        443: "HTTPS",
        445: "SMB",
        587: "SMTP (no cifrado)",
        3306: "MySQL",
        3389: "RDP"
    }  # Lista de puertos "importantes"

    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        return f"Error: No se pudo resolver el host {target}. Verifique su conexión y/o nombre de host.", None

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

    if open_ports:
        ports_info = [f"{port} ({description})" for port, description in open_ports.items()]
        ports_result = f"Puertos abiertos encontrados: {', '.join(ports_info)}"
        return ports_result, open_ports
    else:
        return "No se encontraron puertos abiertos.", None


def check_cookie_security(target_url):
    try:
        response = requests.get(target_url)
    except requests.RequestException:
        return "No se pudo establecer una conexion con la URL proporcionada.", {}

    cookies_issues = []
    report = ""

    # Obtener la lista de cookies
    cookies = response.headers.get("Set-Cookie", "").split(",")

    if not cookies or cookies == [""]:
        return "La URL proporcionada no establece cookies.", {}

    cookies_values = {}

    for cookie in cookies:
        cookie_name = cookie.split("=")[0]
        cookie_value = cookie.split("=")[1].split(";")[0]
        cookies_values[cookie_name] = cookie_value
        
        # Verificar atributos Secure, HttpOnly y SameSite
        if "secure" not in cookie.lower():
            cookies_issues.append(f"La cookie '{cookie_name}' no tiene el atributo 'Secure'.")
        if "httponly" not in cookie.lower():
            cookies_issues.append(f"La cookie '{cookie_name}' no tiene el atributo 'HttpOnly'.")
        if "samesite" not in cookie.lower():
            cookies_issues.append(f"La cookie '{cookie_name}' no tiene el atributo 'SameSite'.")

        # Verificar la duración de la cookie
        if "max-age" in cookie or "expires" in cookie:
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
    soup = bs(response.text, "html.parser")
    if not soup.find(string=re.compile("política de cookies", re.IGNORECASE)):
        cookies_issues.append("No se encontró una mención explícita sobre la política de cookies en la página.")

    if cookies_issues:
        report += "\n".join(cookies_issues)
    else:
        report = "Las cookies parecen estar bien configuradas."

    return report, cookies_values


def save_to_database(vulnerability_type, target_url, details, payloads=None):
    filename = f"bbdd_{vulnerability_type.lower()}.txt"
    entry = f"------------\n"
    entry += f"URL: {target_url}\n"
    entry += f"Tipo_De_Vulnerabilidad: {vulnerability_type}\n"
    entry += f"Fecha_Detectada: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    entry += f"Detalles: {details}\n"

    if payloads:
        entry += "Payloads Vulnerables:\n"
        for payload in payloads:
            # Asumiendo que los payloads son tuplas donde el segundo elemento es el payload vulnerable
            if isinstance(payload, tuple) and len(payload) > 1:
                payload_to_save = payload[1]
            else:
                payload_to_save = payload
            entry += f"    {payload_to_save}\n"

    with open(filename, "a") as file:
        file.write(entry)


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

    # Escaneo de Puertos
    print("\n[+] Comprobando puertos abiertos...")
    ports_result, open_ports = check_ports(target_url.split("//")[-1].split("/")[0])
    if ports_result:  # Asegúrate de que ports_result no es None antes de guardar
        save_to_database("Ports", target_url, ports_result)
        print(ports_result)
    else:
        print("No se encontraron puertos abiertos o no se pudo completar el escaneo.")

    # Configuración insegura de cookies
    print("\n[+] Comprobando seguridad de cookies...")
    cookie_report, cookies_values = check_cookie_security(target_url)
    if "no tiene el atributo" in cookie_report:
        save_to_database("Cookies", target_url, cookie_report)
    print(cookie_report)

    # XSS
    print("\n[+] Comprobando Cross-Site Scripting (XSS)...")
    xss_result, xss_payloads = check_xss(target_url)  # Solo pasa target_url como argumento
    if xss_result == "Vulnerabilidad XSS detectada":
        save_to_database("XSS", target_url, xss_result, xss_payloads)
    else:
        print("No se han encontrado vulnerabilidades\n")
      
    # SQLi
    print("\n[+] Comprobando SQL Injection...")
    sqli_result, sqli_payloads = check_sqli(target_url, "combined_payloads.txt")
    if sqli_result == "Vulnerabilidad SQLi detectada":
        save_to_database("SQLi", target_url, sqli_result, sqli_payloads)
        print(sqli_result + f" con payloads: {sqli_payloads}")
    else:
        print("No se detectaron vulnerabilidades SQLi.")
        
    # DDoS
    ddos_permission = input("\n¿Tienes permiso para realizar una prueba de robustez DDoS? (s/n): ")
    if ddos_permission.lower() == 's':
        print("\n[+] Comprobando resistencia a DDoS...")
        ddos_result, ddos_details = check_ddos(target_url)
        if ddos_result:  # Asegúrate de que ddos_result no es None antes de imprimir o guardar
            print(ddos_result)
            if "vulnerable" in ddos_result.lower():
                save_to_database("DDoS", target_url, ddos_details)
        else:
            print("No se pudo realizar la comprobación de DDoS o no se encontraron vulnerabilidades.")
            
    # Compilando el informe
    report = "\n----- INFORME FINAL -----\n"
    report += "\n[URL]\n" + target_url
    report += "\n[Puertos Abiertos]\n" + ports_result
    report += "\n[Cookies]\n" + cookie_report
    report += "\n[SQLi]\n" + sqli_result  
    report += "\n[XSS]\n" + xss_result
    if ddos_permission.lower() == 's':
        report += "\n[DDoS]\n" + ddos_result
    print(report)

    # Opcionalmente, guardar este informe en un archivo
    save_option = input("\n¿Deseas guardar el informe en un archivo? (s/n): ")
    if save_option.lower() == 's':
        with open("report.txt", "w") as file:
            file.write(report)
        print("Informe guardado en 'report.txt'")


main()

