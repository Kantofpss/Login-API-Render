import sqlite3
import os
import bcrypt
import pyotp

def get_db_path():
    """Determina o caminho do banco de dados, priorizando o disco do Render."""
    # O Render define RENDER_DISK_PATH se um disco estiver montado.
    render_disk_path = os.environ.get('RENDER_DISK_PATH')
    if render_disk_path:
        # Usa o disco persistente no Render.
        return os.path.join(render_disk_path, 'users.db')
    else:
        # Para desenvolvimento local, cria o db na pasta 'instance'.
        # Isso evita que o banco de dados seja misturado com o código.
        local_path = 'instance'
        if not os.path.exists(local_path):
            os.makedirs(local_path)
        return os.path.join(local_path, 'users.db')

def criar_banco():
    """Cria o banco de dados SQLite e as tabelas necessárias, com caminhos dinâmicos e melhor log de erros."""
    db_path = get_db_path()
    print(f"--- Tentando criar/conectar ao banco de dados em: {db_path} ---")

    conn = None  # Inicializa conn como None
    try:
        # Garante que o diretório de destino exista
        db_dir = os.path.dirname(db_path)
        if not os.path.exists(db_dir):
            print(f"Criando diretório: {db_dir}")
            os.makedirs(db_dir)

        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        print("Conexão com o banco de dados estabelecida com sucesso.")

        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            password TEXT NOT NULL,
            hwid TEXT,
            username TEXT UNIQUE
        )
        ''')

        cursor.execute('''
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            two_factor_secret TEXT
        )
        ''')

        cursor.execute('''
        CREATE TABLE IF NOT EXISTS system_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
        ''')

        cursor.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('system_status', 'online')")
        cursor.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('never_sleep', 'false')")
        cursor.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('system_version', '2.0')")
        print("Tabelas e configurações padrão verificadas/criadas.")

        admin_username = 'Project Kntz'
        admin_password = '157171'
        two_factor_secret = os.environ.get('TWO_FACTOR_SECRET', 'JBSWY3DPEHPK3PXP')
        
        # Verifica se o admin já existe antes de tentar inserir
        cursor.execute('SELECT id FROM admins WHERE username = ?', (admin_username,))
        if cursor.fetchone() is None:
            hashed_password = bcrypt.hashpw(admin_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            cursor.execute('INSERT INTO admins (username, password, two_factor_secret) VALUES (?, ?, ?)',
                           (admin_username, hashed_password, two_factor_secret))
            print(f"Administrador '{admin_username}' criado.")
        else:
            print(f"Administrador '{admin_username}' já existe.")

        conn.commit()
        print("--- Banco de dados configurado com sucesso! ---")
        
    except Exception as e:
        # Captura QUALQUER erro (permissão, I/O, SQL, etc.) e o exibe
        print(f"!!!!!! ERRO CRÍTICO AO CONFIGURAR O BANCO DE DADOS !!!!!!")
        print(f"Erro: {e}")
        print(f"Tipo de erro: {type(e).__name__}")
        # Levanta a exceção para interromper o processo se a criação do DB falhar
        raise
    finally:
        if conn:
            conn.close()
            print("Conexão com o banco de dados fechada.")

if __name__ == "__main__":
    criar_banco()