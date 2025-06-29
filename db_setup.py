import sqlite3
import os
import bcrypt

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
    """Cria o banco de dados e as tabelas, sem os campos de 2FA."""
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

        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            password TEXT NOT NULL,
            hwid TEXT,
            username TEXT UNIQUE,
            expiration_date TEXT
        )
        ''')
        print("Tabela 'users' verificada/criada.")

        # --- MODIFICADO: Removida a coluna two_factor_secret ---
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
        ''')
        print("Tabela 'admins' verificada/criada (sem 2FA).")

        cursor.execute('''
        CREATE TABLE IF NOT EXISTS system_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
        ''')
        print("Tabela 'system_settings' verificada/criada.")

        cursor.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('system_status', 'online')")
        cursor.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('never_sleep', 'false')")
        cursor.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('system_version', '2.0')")
        cursor.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('expected_client_hash', 'default_hash_placeholder')")
        print("Configurações padrão do sistema verificadas.")

        admin_username = 'Project Kntz'
        admin_password = '157171'
        
        cursor.execute('SELECT id FROM admins WHERE username = ?', (admin_username,))
        if cursor.fetchone() is None:
            hashed_password = bcrypt.hashpw(admin_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            # --- MODIFICADO: Inserção do admin sem o campo de 2FA ---
            cursor.execute('INSERT INTO admins (username, password) VALUES (?, ?)',
                           (admin_username, hashed_password))
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