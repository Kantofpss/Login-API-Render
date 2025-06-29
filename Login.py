import os
import time
import subprocess
import hashlib
import sys
import requests
from colorama import *

init(autoreset=True)

CLIENT_VERSION = "2.0"  # Versão deste cliente. Mude para a versão esperada pelo servidor.

CHAVE_VERIFICACAO = os.environ.get('VERIFICATION_KEY', 'em-uma-noite-escura-as-corujas-observam-42')
CRAFT_URL = os.environ.get('CRAFT_URL', 'https://login-netfly.onrender.com')

class Cores:
    BRIGHT, RESET = Style.BRIGHT, Style.RESET_ALL
    AZUL, AMARELO, VERDE, VERMELHO, BRANCO, MAGENTA = Fore.CYAN + BRIGHT, Fore.YELLOW + BRIGHT, Fore.GREEN + BRIGHT, Fore.RED + BRIGHT, Fore.WHITE + BRIGHT, Fore.MAGENTA + BRIGHT
    BANNER, TITULO, BORDA, TEXTO, DESTAQUE = AZUL, AMARELO, BRANCO, Fore.LIGHTWHITE_EX, MAGENTA
    SUCESSO, ERRO, AVISO, INFO, STATUS = VERDE, VERMELHO, AMARELO, AZUL, BRANCO
    PROMPT, INPUT, HWID = BRANCO, Fore.LIGHTCYAN_EX, AZUL

def verificar_debugger():
    if sys.gettrace() is not None:
        print(f"{Cores.ERRO}Falha na inicialização do componente de segurança. Encerrando.")
        time.sleep(1)
        os._exit(1)

# --- NOVA FUNÇÃO ADICIONADA: Calcula o hash do próprio executável ---
def calculate_self_hash():
    """Calcula o SHA256 hash do próprio executável em tempo de execução."""
    try:
        # sys.executable retorna o caminho para o executável atual.
        # Em um script .py, é o interpretador. Em um PyInstaller .exe, é o .exe.
        with open(sys.executable, 'rb') as f:
            bytes_content = f.read()
            return hashlib.sha256(bytes_content).hexdigest()
    except Exception as e:
        print(f"{Cores.ERRO}Erro ao calcular hash do executável: {e}")
        return "HASH_ERROR"
# ------------------------------------------------------------------

def pre_login_check():
    """Verifica o status do sistema e a versão antes de prosseguir."""
    limpar_tela()
    print(Cores.BANNER + "Iniciando KNTZ...")
    print(f"{Cores.INFO}[*] Verificando status e versão do sistema...")
    time.sleep(1)
    try:
        url_check = f"{CRAFT_URL}/api/check-status"
        response = requests.get(url_check, timeout=15)
        response.raise_for_status()  # Lança um erro para respostas 4xx/5xx

        data = response.json()
        server_status = data.get('system_status', 'offline')
        server_version = data.get('system_version', '0.0')

        if server_status != 'online':
            print(f"\n{Cores.ERRO}[!] O sistema está temporariamente offline.")
            print(f"{Cores.AVISO}Por favor, tente novamente mais tarde. Encerrando em 3 segundos...")
            time.sleep(3)
            os._exit(1)
        
        if server_version != CLIENT_VERSION:
            print(f"\n{Cores.ERRO}[!] VERSÃO INVÁLIDA!")
            print(f"{Cores.AVISO}Sua versão ({CLIENT_VERSION}) está desatualizada. A versão necessária é {server_version}.")
            print(f"{Cores.AVISO}Por favor, baixe a nova versão. Encerrando em 3 segundos...")
            time.sleep(3)
            os._exit(1)

        print(f"{Cores.SUCESSO}[OK] Sistema online e atualizado (Versão {CLIENT_VERSION}).")
        time.sleep(1)

    except requests.exceptions.RequestException as e:
        print(f"\n{Cores.ERRO}[!] Falha na conexão com o servidor de autenticação.")
        print(f"{Cores.AVISO}Verifique sua conexão com a internet. Encerrando em 3 segundos...")
        time.sleep(3)
        os._exit(1)

def get_hwid():
    try:
        comando = 'wmic diskdrive get serialnumber'
        resultado = subprocess.check_output(comando, shell=True, text=True, stderr=subprocess.DEVNULL)
        linhas = resultado.strip().split('\n')
        hwid_bruto = linhas[1].strip() if len(linhas) > 1 else "DefaultHWID"
        return hashlib.sha256(hwid_bruto.encode()).hexdigest()
    except Exception:
        return "ERRO_AO_OBTER_HWID_DISCO"

def limpar_tela():
    os.system('cls' if os.name == 'nt' else 'clear')

def exibir_banner_principal():
    banner_arte = r"""

██╗  ██╗███╗   ██╗████████╗███████╗
██║ ██╔╝████╗  ██║╚══██╔══╝╚══███╔╝
█████╔╝ ██╔██╗ ██║   ██║     ███╔╝ 
██╔═██╗ ██║╚██╗██║   ██║    ███╔╝  
██║  ██╗██║ ╚████║   ██║   ███████╗
╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝
                                   

    """
    info = f"""
{Cores.BORDA}======================================================
{Cores.STATUS}[*] Auth System        : {Cores.SUCESSO}Online Server
{Cores.STATUS}[*] Security Source    : {Cores.SUCESSO}HWID Lock & Client Hash
{Cores.STATUS}[*] Client Version     : {Cores.BRANCO}{CLIENT_VERSION}
{Cores.BORDA}======================================================
"""
    print(Cores.BANNER + banner_arte)
    print(info)

def menu_principal():
    menu_texto = f"""
{Cores.PROMPT}[1] Login
{Cores.PROMPT}[3] {Cores.AVISO}Mostrar meu HWID
{Cores.PROMPT}[0] Exit
    """
    print(menu_texto)

def tela_de_login_servidor():
    verificar_debugger()
    try:
        URL_LOGIN = f"{CRAFT_URL}/api/login"
        limpar_tela()
        exibir_banner_principal()
        print(Cores.TITULO + "--- TELA DE LOGIN ---\n")
        usuario_input = input(f"{Cores.PROMPT}[?] Digite seu usuário: {Cores.INPUT}")
        key_input = input(f"{Cores.PROMPT}[?] Digite sua senha: {Cores.INPUT}")
        hwid_atual = get_hwid()
        client_exe_hash = calculate_self_hash() # Calcula o hash do executável

        dados_de_login = {
            "usuario": usuario_input,
            "key": key_input,
            "hwid": hwid_atual,
            "verification_key": CHAVE_VERIFICACAO,
            "client_hash": client_exe_hash # Envia o hash do executável
        }
        print(f"\n{Cores.INFO}[*] Conectando ao servidor de autenticação...")
        response = requests.post(URL_LOGIN, json=dados_de_login, timeout=60)
        resposta_json = response.json()
        if response.status_code in [200, 201] and resposta_json.get("status") == "sucesso":
            print(f"\n{Cores.SUCESSO}[SUCCESS] {resposta_json.get('mensagem')}")
            time.sleep(2)
            return usuario_input
        else:
            mensagem_erro = resposta_json.get("mensagem", "Erro desconhecido do servidor.")
            print(f"\n{Cores.ERRO}[ERROR] {mensagem_erro} (Código: {response.status_code})")
            time.sleep(3)
            return None
    except requests.exceptions.RequestException:
        print(f"{Cores.ERRO}\n[ERROR] A conexão com o servidor de autenticação falhou. Verifique sua internet ou tente mais tarde.")
        time.sleep(3)
        return None
    except Exception as e:
        print(f"{Cores.ERRO}\n[ERROR] Ocorreu um erro inesperado: {e}")
        time.sleep(3)
        return None

def tela_logado(nome_usuario):
    while True:
        limpar_tela()
        hwid_curto = get_hwid()[:10]
        tela_logado_texto = f"""
{Cores.SUCESSO}ACESSO AUTORIZADO
{Cores.BORDA}======================================================
{Cores.PROMPT}Bem-vindo, {Cores.INFO}{nome_usuario}{Cores.PROMPT}!
{Cores.TEXTO}Licença vinculada ao HWID: {Cores.SUCESSO}{hwid_curto}...
{Cores.BORDA}======================================================

{Cores.PROMPT}[1] Executar Kntz
{Cores.PROMPT}[2] Executar Ferramenta B
{Cores.PROMPT}[3] Logout
        """
        print(tela_logado_texto)
        try:
            escolha = input(f"{Cores.PROMPT}[+] Escolha uma opção: {Cores.INPUT}")
            if escolha == '1':
                print(f"{Cores.SUCESSO}\n[+] Executando Kntz...")
                try:
                    subprocess.run([sys.executable, 'kntz.py'], check=True)
                except subprocess.CalledProcessError as e:
                    print(f"{Cores.ERRO}\n[!] Erro ao executar kntz.py: {e}")
                except FileNotFoundError:
                    print(f"{Cores.ERRO}\n[!] Arquivo kntz.py não encontrado.")
                time.sleep(2)
            elif escolha == '2':
                print(f"{Cores.AVISO}\n[*] Executando a ferramenta B...")
                time.sleep(2)
            elif escolha == '3':
                print(f"{Cores.AVISO}\n[*] Fazendo logout...")
                time.sleep(1)
                return
            else:
                print(f"{Cores.ERRO}\n[!] Opção inválida.")
                time.sleep(2)
        except KeyboardInterrupt:
            print(f"{Cores.ERRO}\n\n[!] Logout forçado. Saindo...")
            os._exit(0)

def main():
    verificar_debugger()
    pre_login_check() # Verifica status e versão antes de exibir o menu
    
    while True:
        limpar_tela()
        exibir_banner_principal()
        menu_principal()
        escolha = input(f"{Cores.PROMPT}[+] Escolha uma opção: {Cores.INPUT}")
        if escolha == '1':
            usuario_logado = tela_de_login_servidor()
            if usuario_logado:
                tela_logado(usuario_logado)
        elif escolha == '3':
            hwid = get_hwid()
            limpar_tela()
            print(f"{Cores.TITULO}--- SEU HARDWARE ID (HWID do Disco) ---\n")
            print(f"{Cores.HWID}{hwid}")
            input(f"\n{Cores.PROMPT}Pressione Enter para voltar ao menu...")
        elif escolha == '0':
            print(f"{Cores.AVISO}Saindo...")
            time.sleep(1)
            break
        else:
            print(f"{Cores.ERRO}[!] Opção inválida, tente novamente.")
            time.sleep(2)

if __name__ == "__main__":
    main()