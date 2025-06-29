import os
import time
import subprocess
import hashlib
import sys
import requests
import threading
from colorama import *
from datetime import datetime, timezone  # <-- IMPORTAÇÃO ADICIONADA

# Tenta importar o psutil, se não conseguir, instala e importa.
try:
    import psutil
except ImportError:
    print("Biblioteca 'psutil' não encontrada. Tentando instalar...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "psutil"])
        import psutil
    except Exception as e:
        print(f"Falha ao instalar psutil. Por favor, instale manualmente com 'pip install psutil'. Erro: {e}")
        time.sleep(5)
        sys.exit(1)


# Desativa avisos de SSL inseguro (se necessário)
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Inicializa o Colorama
init(autoreset=True)

# --- Configurações Globais ---
CLIENT_VERSION = "2.0"
CRAFT_URL = os.environ.get('CRAFT_URL', 'https://login-netfly.onrender.com')

class Cores:
    BRIGHT, RESET = Style.BRIGHT, Style.RESET_ALL
    AZUL, AMARELO, VERDE, VERMELHO, BRANCO, MAGENTA = Fore.CYAN + BRIGHT, Fore.YELLOW + BRIGHT, Fore.GREEN + BRIGHT, Fore.RED + BRIGHT, Fore.WHITE + BRIGHT, Fore.MAGENTA + BRIGHT
    BANNER, TITULO, BORDA, TEXTO, DESTAQUE = AZUL, AMARELO, BRANCO, Fore.LIGHTWHITE_EX, MAGENTA
    SUCESSO, ERRO, AVISO, INFO, STATUS = VERDE, VERMELHO, AMARELO, AZUL, BRANCO
    PROMPT, INPUT, HWID = BRANCO, Fore.LIGHTCYAN_EX, AZUL

# --- Sistema de Segurança Anti-Cracking ---
BLACKLIST_PROCESSOS = [
    # Debuggers Populares
    "idaq.exe", "idaq64.exe", "x64dbg.exe", "x32dbg.exe", "ollydbg.exe",
    "gdb.exe", "windbg.exe", "edb.exe",
    # Descompiladores e Ferramentas de Análise Reversa
    "dnspy.exe", "ghidra.exe", "cutter.exe", "binaryninja.exe", "malcat.exe", "reclass.net.exe",
    # Ferramentas de Análise de Memória e Rede
    "cheatengine-x86_64.exe", "cheatengine-i386.exe", "charles.exe",
    "fiddler.exe", "wireshark.exe", "procmon.exe", "processhacker.exe",
    "httpdebuggerui.exe", "tcpview.exe"
]

def get_hwid():
    """Obtém um HWID único do disco serial."""
    try:
        comando = 'wmic diskdrive get serialnumber'
        resultado = subprocess.check_output(comando, shell=True, text=True, stderr=subprocess.DEVNULL)
        linhas = resultado.strip().split('\n')
        hwid_bruto = linhas[1].strip() if len(linhas) > 1 else "DefaultHWID_Error"
        return hashlib.sha256(hwid_bruto.encode()).hexdigest()
    except Exception:
        # Fallback para outro método se wmic falhar
        try:
            uuid_out = subprocess.check_output(['wmic', 'csproduct', 'get', 'uuid']).decode().split('\n')[1].strip()
            return hashlib.sha256(uuid_out.encode()).hexdigest()
        except Exception:
            return "ERRO_AO_OBTER_HWID"

def reportar_violacao_e_sair(processo_detectado):
    """Envia um relatório de violação para o servidor e encerra o aplicativo de forma segura."""
    hwid = get_hwid()
    limpar_tela()
    print(f"\n{Cores.ERRO}[!] VIOLAÇÃO DE SEGURANÇA DETECTADA!")
    print(f"{Cores.ERRO}    Ferramenta não autorizada em execução: {Cores.BRANCO}{processo_detectado}")
    print(f"{Cores.AVISO}    Esta atividade viola os termos de serviço.")
    print(f"{Cores.AVISO}    Um relatório foi enviado e seu acesso foi permanentemente revogado.")

    try:
        url_report = f"{CRAFT_URL}/api/report-violation"
        requests.post(url_report, json={"hwid": hwid, "reason": f"Ferramenta detectada: {processo_detectado}"}, timeout=10, verify=False)
    except requests.exceptions.RequestException:
        # A falha em reportar não deve impedir o encerramento do cliente.
        pass

    print(f"\n{Cores.BRANCO}Encerrando em 5 segundos...")
    time.sleep(5)
    os._exit(1) # Encerra o processo imediatamente e de forma segura.

def monitor_de_seguranca():
    """Thread que monitora processos em segundo plano para detectar ferramentas de cracking."""
    processos_conhecidos = {p.name().lower() for p in psutil.process_iter(['name'])}

    while True:
        try:
            # Itera sobre os processos em execução
            for p in psutil.process_iter(['name']):
                nome_processo = p.info['name'].lower()
                if nome_processo in BLACKLIST_PROCESSOS and nome_processo not in processos_conhecidos:
                    reportar_violacao_e_sair(nome_processo)

            # Atualiza a lista de processos conhecidos para a próxima verificação
            processos_conhecidos = {p.name().lower() for p in psutil.process_iter(['name'])}
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            # Ignora erros se um processo for fechado durante a iteração
            continue
        time.sleep(2) # Pausa otimizada para não consumir muito CPU

def verificar_debugger_anexado():
    """Verifica se um debugger está anexado ao processo."""
    if sys.gettrace() is not None:
        reportar_violacao_e_sair("Debugger Anexado")

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
{Cores.STATUS}[*] Security Source    : {Cores.SUCESSO}HWID Lock & Anti-Crack Pro
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

def pre_login_check():
    """Verifica o status do sistema e a versão antes de prosseguir."""
    limpar_tela()
    print(Cores.BANNER + "Iniciando KNTZ...")
    print(f"{Cores.INFO}[*] Verificando status e versão do sistema...")
    time.sleep(1)
    try:
        url_check = f"{CRAFT_URL}/api/system-settings"

        response = requests.get(url_check, timeout=60, verify=False)
        response.raise_for_status()

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
        print(f"{Cores.AVISO}Verifique sua conexão com a internet.")
        print(f"{Cores.AVISO}Encerrando em 10 segundos...")
        time.sleep(10)
        os._exit(1)

def tela_de_login_servidor():
    verificar_debugger_anexado()
    try:
        URL_LOGIN = f"{CRAFT_URL}/api/login"
        limpar_tela()
        exibir_banner_principal()
        print(Cores.TITULO + "--- TELA DE LOGIN ---\n")
        usuario_input = input(f"{Cores.PROMPT}[?] Digite seu usuário: {Cores.INPUT}")
        key_input = input(f"{Cores.PROMPT}[?] Digite sua senha: {Cores.INPUT}")

        # --- CORRIGIDO: O nome do campo foi ajustado de "key" para "senha" ---
        dados_de_login = {
            "usuario": usuario_input,
            "senha": key_input,
            "hwid": get_hwid(),
            "client_version": CLIENT_VERSION
        }

        print(f"\n{Cores.INFO}[*] Conectando ao servidor de autenticação...")
        response = requests.post(URL_LOGIN, json=dados_de_login, timeout=60, verify=False)
        resposta_json = response.json()

        if response.status_code in [200, 201] and resposta_json.get("status") == "sucesso":
            print(f"\n{Cores.SUCESSO}[SUCCESS] {resposta_json.get('mensagem')}")

            # --- NOVO: Extrai e exibe o tempo de acesso restante ---
            expiration_date_str = resposta_json.get('expiration_date')
            if expiration_date_str:
                try:
                    # Converte a data do servidor (ISO format com timezone) para um objeto datetime
                    expiration_date = datetime.fromisoformat(expiration_date_str)
                    # Pega a data e hora atual com timezone UTC
                    now_utc = datetime.now(timezone.utc)
                    # Calcula a diferença
                    time_left = expiration_date - now_utc

                    # Formata a exibição do tempo restante
                    if time_left.total_seconds() > 0:
                        days = time_left.days
                        hours, remainder = divmod(time_left.seconds, 3600)
                        minutes, _ = divmod(remainder, 60)
                        print(f"{Cores.INFO}[INFO] Tempo de acesso restante: {Cores.BRANCO}{days} dias, {hours} horas e {minutes} minutos.")
                    else:
                        print(f"{Cores.AVISO}[INFO] Seu tempo de acesso já expirou.")

                except Exception as e:
                    # Caso haja algum erro no parsing da data, não quebra o login
                    print(f"{Cores.AVISO}[AVISO] Não foi possível calcular o tempo de acesso restante.")

            time.sleep(4) # Tempo para o usuário ler as informações
            return usuario_input
        else:
            mensagem_erro = resposta_json.get("mensagem", "Erro desconhecido do servidor.")
            print(f"\n{Cores.ERRO}[ERROR] {mensagem_erro} (Código: {response.status_code})")
            time.sleep(4)
            return None
    except requests.exceptions.RequestException:
        print(f"{Cores.ERRO}\n[ERROR] A conexão com o servidor de autenticação falhou.")
        time.sleep(3)
        return None
    except Exception as e:
        print(f"{Cores.ERRO}\n[ERROR] Ocorreu um erro inesperado: {e}")
        time.sleep(3)
        return None

def main():
    # Primeira verificação de segurança antes de qualquer coisa
    verificar_debugger_anexado()

    # Inicia o monitor de segurança em uma thread separada que não impede o programa de fechar
    monitor_thread = threading.Thread(target=monitor_de_seguranca, daemon=True)
    monitor_thread.start()

    # Continua com as verificações de servidor
    pre_login_check()

    while True:
        verificar_debugger_anexado() # Verifica a cada loop do menu
        limpar_tela()
        exibir_banner_principal()
        menu_principal()
        escolha = input(f"{Cores.PROMPT}[+] Escolha uma opção: {Cores.INPUT}")
        if escolha == '1':
            usuario_logado = tela_de_login_servidor()
            if usuario_logado:
                print(f"{Cores.SUCESSO}Sessão iniciada para {usuario_logado}. O monitoramento de segurança continua ativo.")
                input("\nPressione Enter para deslogar e voltar ao menu...")
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