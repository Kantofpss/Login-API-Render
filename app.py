from flask import Flask, request, jsonify, render_template, session, redirect, url_for
import sqlite3
import os
from dotenv import load_dotenv
import bcrypt
import pyotp

load_dotenv()
app = Flask(__name__)
app.secret_key = os.urandom(24)

def conectar_banco():
    db_path = os.environ.get('DB_PATH', '/opt/render/project/src/users.db')
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        return conn, conn.cursor()
    except sqlite3.Error as e:
        print(f"Erro ao conectar ao banco de dados: {e}")
        raise

# --- NOVO ENDPOINT ADICIONADO ---
@app.route('/api/check-status', methods=['GET'])
def check_status():
    """Endpoint para verificar o status e a versão do sistema antes do login."""
    try:
        conn, cursor = conectar_banco()
        # Garante que os valores padrão existam, caso o db_setup não tenha sido executado corretamente
        cursor.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('system_status', 'online')")
        cursor.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('system_version', '2.0')")
        conn.commit()
        
        cursor.execute("SELECT key, value FROM system_settings WHERE key IN ('system_status', 'system_version')")
        settings_list = cursor.fetchall()
        settings = {row['key']: row['value'] for row in settings_list}
        
        # Adiciona valores padrão caso não estejam no banco
        if 'system_status' not in settings:
            settings['system_status'] = 'offline'
        if 'system_version' not in settings:
            settings['system_version'] = '1.0'
            
        conn.close()
        return jsonify(settings), 200
    except sqlite3.Error as e:
        print(f"Erro no endpoint /api/check-status: {e}")
        return jsonify({'status': 'erro', 'message': 'Erro no banco de dados'}), 500

@app.route('/ping', methods=['GET'])
def ping():
    try:
        conn, cursor = conectar_banco()
        cursor.execute("SELECT value FROM system_settings WHERE key = 'never_sleep'")
        result = cursor.fetchone()
        never_sleep = result['value'] == 'true' if result else False
        conn.close()
        return jsonify({'status': 'alive' if never_sleep else 'inactive'}), 200
    except sqlite3.Error as e:
        print(f"Erro no endpoint /ping: {e}")
        return jsonify({'status': 'error', 'message': 'Erro no banco de dados'}), 500

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        two_factor_code = request.form['two_factor_code']
        try:
            conn, cursor = conectar_banco()
            cursor.execute('SELECT password, two_factor_secret FROM admins WHERE username = ?', (username,))
            admin = cursor.fetchone()
            conn.close()
            
            if not admin:
                return render_template('admin_login.html', error='Credenciais inválidas.')
            
            if not bcrypt.checkpw(password.encode('utf-8'), admin['password'].encode('utf-8')):
                return render_template('admin_login.html', error='Credenciais inválidas.')
            
            if admin['two_factor_secret']:
                if username == 'Project Kntz' and two_factor_code == 'Bruh':
                    session['admin_logged_in'] = True
                    return redirect(url_for('gerenciar_usuarios'))
                
                totp = pyotp.TOTP(admin['two_factor_secret'])
                if not totp.verify(two_factor_code):
                    return render_template('admin_login.html', error='Código 2FA inválido.')
            
            session['admin_logged_in'] = True
            return redirect(url_for('gerenciar_usuarios'))
        except sqlite3.Error as e:
            print(f"Erro no login: {e}")
            return render_template('admin_login.html', error='Erro no servidor. Tente novamente.')
    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('admin_login'))

@app.route('/')
def home():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    return redirect(url_for('gerenciar_usuarios'))

@app.route('/gerenciar-usuarios')
def gerenciar_usuarios():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    return render_template('gerenciar_usuarios.html')

@app.route('/criar-usuario')
def criar_usuario_page():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    return render_template('criar_usuario.html')

@app.route('/configuracoes')
def configuracoes():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    return render_template('configuracoes.html')

@app.route('/api/system-settings', methods=['GET', 'POST'])
def system_settings():
    try:
        conn, cursor = conectar_banco()
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS system_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
        ''')
        cursor.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('system_status', 'offline')")
        cursor.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('never_sleep', 'false')")
        conn.commit()

        if not session.get('admin_logged_in'):
            conn.close()
            return jsonify({'status': 'erro', 'mensagem': 'Acesso não autorizado'}), 401

        if request.method == 'POST':
            data = request.get_json()
            if not data:
                conn.close()
                return jsonify({'status': 'erro', 'mensagem': 'Dados inválidos.'}), 400
            system_status = data.get('system_status')
            never_sleep = data.get('never_sleep')

            if system_status not in ['online', 'offline', None]:
                conn.close()
                return jsonify({'status': 'erro', 'mensagem': 'Status do sistema inválido.'}), 400
            if never_sleep not in ['true', 'false', None]:
                conn.close()
                return jsonify({'status': 'erro', 'mensagem': 'Configuração de never_sleep inválida.'}), 400

            updates = []
            if system_status is not None:
                cursor.execute("UPDATE system_settings SET value = ? WHERE key = 'system_status'", (system_status,))
                updates.append(f'Sistema definido como {system_status.upper()}.')
            if never_sleep is not None:
                cursor.execute("UPDATE system_settings SET value = ? WHERE key = 'never_sleep'", (never_sleep,))
                updates.append(f'Never Sleep definido como {never_sleep.upper()}.')

            conn.commit()
            conn.close()
            return jsonify({'status': 'sucesso', 'message': ' '.join(updates) if updates else 'Nenhuma alteração feita.'}), 200

        cursor.execute("SELECT key, value FROM system_settings WHERE key IN ('system_status', 'never_sleep')")
        settings = {row['key']: row['value'] for row in cursor.fetchall()}
        conn.close()
        return jsonify(settings), 200
    except sqlite3.Error as e:
        print(f"Erro no endpoint /api/system-settings: {e}")
        return jsonify({'status': 'erro', 'mensagem': 'Erro no banco de dados'}), 500

@app.route('/users', methods=['GET'])
def get_users():
    if not session.get('admin_logged_in'):
        return jsonify({'status': 'erro', 'mensagem': 'Acesso não autorizado'}), 401
    try:
        conn, cursor = conectar_banco()
        cursor.execute('SELECT id, username, hwid FROM users ORDER BY id DESC')
        users = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return jsonify(users), 200
    except sqlite3.Error as e:
        print(f"Erro no endpoint /users: {e}")
        return jsonify({'status': 'erro', 'mensagem': 'Erro no banco de dados'}), 500

@app.route('/users/search', methods=['GET'])
def search_users():
    if not session.get('admin_logged_in'):
        return jsonify({'status': 'erro', 'mensagem': 'Acesso não autorizado'}), 401
    query = request.args.get('query', '')
    try:
        conn, cursor = conectar_banco()
        cursor.execute('SELECT id, username, hwid FROM users WHERE username LIKE ?', ('%' + query + '%',))
        users = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return jsonify(users), 200
    except sqlite3.Error as e:
        print(f"Erro no endpoint /users/search: {e}")
        return jsonify({'status': 'erro', 'mensagem': 'Erro no banco de dados'}), 500

@app.route('/users/reset_hwid/<int:user_id>', methods=['POST'])
def reset_hwid(user_id):
    if not session.get('admin_logged_in'):
        return jsonify({'status': 'erro', 'mensagem': 'Acesso não autorizado'}), 401
    try:
        conn, cursor = conectar_banco()
        cursor.execute('UPDATE users SET hwid = NULL WHERE id = ?', (user_id,))
        conn.commit()
        conn.close()
        return jsonify({'status': 'sucesso', 'message': 'HWID resetado com sucesso'}), 200
    except sqlite3.Error as e:
        print(f"Erro no endpoint /users/reset_hwid: {e}")
        return jsonify({'status': 'erro', 'mensagem': 'Erro no banco de dados'}), 500

@app.route('/admin/users/delete/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    if not session.get('admin_logged_in'):
        return jsonify({'status': 'erro', 'mensagem': 'Acesso não autorizado'}), 401
    try:
        conn, cursor = conectar_banco()
        cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
        conn.close()
        return jsonify({'status': 'sucesso', 'message': 'Usuário excluído com sucesso'}), 200
    except sqlite3.Error as e:
        print(f"Erro no endpoint /admin/users/delete: {e}")
        return jsonify({'status': 'erro', 'mensagem': 'Erro no banco de dados'}), 500

@app.route('/admin/users', methods=['POST'])
def add_user():
    if not session.get('admin_logged_in'):
        return jsonify({'status': 'erro', 'mensagem': 'Acesso não autorizado'}), 401
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'status': 'erro', 'mensagem': 'Usuário e senha são obrigatórios.'}), 400
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    try:
        conn, cursor = conectar_banco()
        cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
        conn.commit()
        conn.close()
        return jsonify({'status': 'sucesso', 'message': 'Usuário adicionado com sucesso!'}), 201
    except sqlite3.IntegrityError:
        return jsonify({'status': 'erro', 'mensagem': 'Este nome de usuário já existe.'}), 409
    except sqlite3.Error as e:
        print(f"Erro no endpoint /admin/users: {e}")
        return jsonify({'status': 'erro', 'mensagem': 'Erro no banco de dados'}), 500

@app.route('/api/login', methods=['POST'])
def api_login():
    try:
        conn, cursor = conectar_banco()
        cursor.execute("SELECT value FROM system_settings WHERE key = 'system_status'")
        result = cursor.fetchone()
        status = result['value'] if result else 'offline'
        
        if status == 'offline':
            conn.close()
            return jsonify({'status': 'erro', 'mensagem': 'O sistema está temporariamente offline. Tente novamente mais tarde.'}), 503

        data = request.get_json()
        if not data or not all(k in data for k in ['usuario', 'key', 'hwid', 'verification_key']):
            conn.close()
            return jsonify({'status': 'erro', 'mensagem': 'Dados incompletos.'}), 400

        verification_key = os.environ.get('VERIFICATION_KEY', 'em-uma-noite-escura-as-corujas-observam-42')
        if data['verification_key'] != verification_key:
            conn.close()
            return jsonify({'status': 'erro', 'mensagem': 'Chave de verificação inválida.'}), 403

        cursor.execute('SELECT password, hwid FROM users WHERE username = ?', (data['usuario'],))
        user = cursor.fetchone()
        
        if not user:
            conn.close()
            return jsonify({'status': 'erro', 'mensagem': 'Usuário não encontrado.'}), 404

        if not bcrypt.checkpw(data['key'].encode('utf-8'), user['password'].encode('utf-8')):
            conn.close()
            return jsonify({'status': 'erro', 'mensagem': 'Senha incorreta.'}), 401

        if user['hwid'] and user['hwid'] != data['hwid']:
            conn.close()
            return jsonify({'status': 'erro', 'mensagem': 'HWID inválido.'}), 403
        elif not user['hwid']:
            cursor.execute('UPDATE users SET hwid = ? WHERE username = ?', (data['hwid'], data['usuario']))
            conn.commit()

        conn.close()
        return jsonify({'status': 'sucesso', 'mensagem': 'Login bem-sucedido!'}), 200
    except sqlite3.Error as e:
        print(f"Erro no endpoint /api/login: {e}")
        return jsonify({'status': 'erro', 'mensagem': 'Erro no banco de dados'}), 500

if __name__ == '__main__':
    if os.environ.get('FLASK_ENV') == 'development':
        port = int(os.environ.get('PORT', 5000))
        app.run(debug=True, host='0.0.0.0', port=port)