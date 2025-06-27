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
    db_path = os.path.join(os.getcwd(), 'users.db')
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn, conn.cursor()

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        two_factor_code = request.form['two_factor_code']
        conn, cursor = conectar_banco()
        cursor.execute('SELECT password, two_factor_secret FROM admins WHERE username = ?', (username,))
        admin = cursor.fetchone()
        conn.close()
        
        if not admin:
            return render_template('admin_login.html', error='Credenciais inválidas.')
        
        # Verifica a senha
        if not bcrypt.checkpw(password.encode('utf-8'), admin['password'].encode('utf-8')):
            return render_template('admin_login.html', error='Credenciais inválidas.')
        
        # Verifica o código 2FA, se o segredo existir
        if admin['two_factor_secret']:
            # Fallback para teste: aceita "Bruh" para o admin padrão
            if username == 'Project Kntz' and two_factor_code == 'Bruh':
                session['admin_logged_in'] = True
                return redirect(url_for('gerenciar_usuarios'))
            
            # Verificação TOTP normal
            totp = pyotp.TOTP(admin['two_factor_secret'])
            if not totp.verify(two_factor_code):
                return render_template('admin_login.html', error='Código 2FA inválido.')
        
        session['admin_logged_in'] = True
        return redirect(url_for('gerenciar_usuarios'))
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

@app.route('/api/system-status', methods=['GET', 'POST'])
def system_status():
    conn, cursor = conectar_banco()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS system_settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    ''')
    cursor.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('system_status', 'offline')")
    conn.commit()

    cursor.execute("SELECT value FROM system_settings WHERE key = 'system_status'")
    result = cursor.fetchone()
    status = result['value'] if result else 'offline'
    conn.close()

    if not session.get('admin_logged_in'):
        return jsonify({'status': 'erro', 'mensagem': 'Acesso não autorizado'}), 401

    if request.method == 'POST':
        data = request.get_json()
        new_status = data.get('status')
        if new_status not in ['online', 'offline']:
            return jsonify({'message': 'Status inválido.'}), 400
        
        conn, cursor = conectar_banco()
        cursor.execute("UPDATE system_settings SET value = ? WHERE key = 'system_status'", (new_status,))
        conn.commit()
        conn.close()
        return jsonify({'message': f'Sistema definido como {new_status.upper()}.'}), 200
    
    return jsonify({'status': status}), 200

@app.route('/users', methods=['GET'])
def get_users():
    if not session.get('admin_logged_in'):
        return jsonify({'message': 'Acesso não autorizado'}), 401
    conn, cursor = conectar_banco()
    cursor.execute('SELECT id, username, hwid FROM users ORDER BY id DESC')
    users = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(users), 200

@app.route('/users/search', methods=['GET'])
def search_users():
    if not session.get('admin_logged_in'):
        return jsonify({'message': 'Acesso não autorizado'}), 401
    query = request.args.get('query', '')
    conn, cursor = conectar_banco()
    cursor.execute('SELECT id, username, hwid FROM users WHERE username LIKE ?', ('%' + query + '%',))
    users = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(users), 200

@app.route('/users/reset_hwid/<int:user_id>', methods=['POST'])
def reset_hwid(user_id):
    if not session.get('admin_logged_in'):
        return jsonify({'message': 'Acesso não autorizado'}), 401
    conn, cursor = conectar_banco()
    cursor.execute('UPDATE users SET hwid = NULL WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    return jsonify({'message': 'HWID resetado com sucesso'}), 200

@app.route('/admin/users/delete/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    if not session.get('admin_logged_in'):
        return jsonify({'message': 'Acesso não autorizado'}), 401
    conn, cursor = conectar_banco()
    cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Usuário excluído com sucesso'}), 200

@app.route('/admin/users', methods=['POST'])
def add_user():
    if not session.get('admin_logged_in'):
        return jsonify({'message': 'Acesso não autorizado'}), 401
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'message': 'Usuário e senha são obrigatórios.'}), 400
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    conn, cursor = conectar_banco()
    try:
        cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
        conn.commit()
        return jsonify({'message': 'Usuário adicionado com sucesso!'}), 201
    except sqlite3.IntegrityError:
        return jsonify({'message': 'Este nome de usuário já existe.'}), 409
    finally:
        conn.close()

@app.route('/api/login', methods=['POST'])
def api_login():
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

    if data['verification_key'] != "em-uma-noite-escura-as-corujas-observam-42":
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

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=True, host='0.0.0.0', port=port)