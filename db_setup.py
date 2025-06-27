import sqlite3
import os
import bcrypt
import pyotp

def criar_banco():
    """Cria o banco de dados SQLite e as tabelas necessárias, incluindo suporte para 2FA."""
    db_path = os.path.join(os.getcwd(), 'users.db')
    if not os.path.exists(os.path.dirname(db_path)):
        os.makedirs(os.path.dirname(db_path))
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Tabela de usuários (sem alterações)
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        password TEXT NOT NULL,
        hwid TEXT,
        username TEXT UNIQUE
    )
    ''')
    
    # Tabela de administradores com campo two_factor_secret
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        two_factor_secret TEXT
    )
    ''')

    # Tabela para configurações do sistema
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS system_settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    ''')
    
    # Insere o estado inicial do sistema como 'online'
    cursor.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('system_status', 'online')")

    # Inserção do admin padrão com 2FA secret fixo
    admin_username = 'Project Kntz'
    admin_password = '157171'
    two_factor_secret = 'JBSWY3DPEHPK3PXP'  # Segredo fixo para TOTP
    if admin_password:  # Garante que a senha não é vazia
        hashed_password = bcrypt.hashpw(admin_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        cursor.execute('INSERT OR IGNORE INTO admins (username, password, two_factor_secret) VALUES (?, ?, ?)', 
                       (admin_username, hashed_password, two_factor_secret))
    
    conn.commit()
    conn.close()
    print("Banco de dados verificado e atualizado com sucesso.")
    print(f"Segredo 2FA para {admin_username}: {two_factor_secret}")
    print("Escaneie o QR code com um app autenticador (como Google Authenticator) usando este URI:")
    print(pyotp.totp.TOTP(two_factor_secret).provisioning_uri(name=admin_username, issuer_name="Project Kntz"))
    print("Ou insira o segredo manualmente no seu app autenticador.")

if __name__ == "__main__":
    criar_banco()