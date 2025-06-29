import sqlite3
import os
import bcrypt
import pyotp

def get_db_path():
    """Determina o caminho do banco de dados, priorizando o disco do Render."""
    render_disk_path = os.environ.get('RENDER_DISK_PATH')
    if render_disk_path:
        return os.path.join(render_disk_path, 'users.db')
    else:
        local_path = 'instance'
        if not os.path.exists(local_path):
            os.makedirs(local_path)
        return os.path.join(local_path, 'users.db')

def criar_banco():
    """Cria o banco de dados e as tabelas, incluindo os novos campos para banimento."""
    db_path = get_db_path()
    print(f"--- Conectando ao banco de dados em: {db_path} ---")

    conn = None
    try:
        db_dir = os.path.dirname(db_path)
        if not os.path.exists(db_dir):
            os.makedirs(db_dir)

        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        print("Conexão estabelecida.")

        # --- CORRIGIDO: Removida a coluna 'name' que não era utilizada ---
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT NOT NULL,
            hwid TEXT,
            expiration_date TEXT,
            is_banned INTEGER DEFAULT 0,
            ban_reason TEXT
        )
        ''')
        print("Tabela 'users' verificada/criada.")


        cursor.execute('''
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            two_factor_secret TEXT
        )
        ''')
        print("Tabela 'admins' verificada/criada.")


        cursor.execute('''
        CREATE TABLE IF NOT EXISTS system_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
        ''')
        print("Tabela 'system_settings' verificada/criada.")

        # Insere configurações padrão sem risco de duplicatas
        cursor.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('system_status', 'online')")
        cursor.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('never_sleep', 'false')")
        cursor.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('system_version', '2.0')")
        cursor.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('expected_client_hash', 'default_hash_placeholder')")
        print("Configurações padrão do sistema verificadas.")

        # Cria o administrador padrão se ele não existir
        admin_username = 'Project Kntz'
        admin_password = '157171'
        two_factor_secret = os.environ.get('TWO_FACTOR_SECRET', 'JBSWY3DPEHPK3PXP')
        
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
        print(f"!!!!!! ERRO CRÍTICO AO CONFIGURAR O BANCO DE DADOS: {e} !!!!!!")
        raise
    finally:
        if conn:
            conn.close()
            print("Conexão com o banco de dados fechada.")

if __name__ == "__main__":
    criar_banco()