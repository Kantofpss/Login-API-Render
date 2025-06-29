from flask import Flask, request, jsonify, render_template, session, redirect, url_for
import sqlite3
import os
from dotenv import load_dotenv
import bcrypt
from datetime import datetime, timedelta, timezone

load_dotenv()
app = Flask(__name__)
app.secret_key = os.urandom(24)

def get_db_path():
    render_disk_path = os.environ.get('RENDER_DISK_PATH', 'instance')
    if not os.path.exists(render_disk_path):
        os.makedirs(render_disk_path)
    return os.path.join(render_disk_path, 'users.db')

def conectar_banco():
    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    return conn, conn.cursor()

# --- Rotas do Painel e Autenticação de Admin ---
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn, cursor = conectar_banco()
        cursor.execute('SELECT password FROM admins WHERE username = ?', (username,))
        admin = cursor.fetchone()
        conn.close()
        if admin and bcrypt.checkpw(password.encode('utf-8'), admin['password'].encode('utf-8')):
            session['admin_logged_in'] = True
            return redirect(url_for('gerenciar_usuarios'))
        return render_template('admin_login.html', error='Credenciais inválidas.')
    return render_template('admin_login.html')

@app.route('/')
def home():
    return redirect(url_for('admin_login'))

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('admin_login'))

# --- Páginas do Painel ---
@app.route('/gerenciar-usuarios')
def gerenciar_usuarios():
    if not session.get('admin_logged_in'): return redirect(url_for('admin_login'))
    return render_template('gerenciar_usuarios.html')

@app.route('/criar-usuario')
def criar_usuario_page():
    if not session.get('admin_logged_in'): return redirect(url_for('admin_login'))
    return render_template('criar_usuario.html')

@app.route('/configuracoes')
def configuracoes():
    if not session.get('admin_logged_in'): return redirect(url_for('admin_login'))
    return render_template('configuracoes.html')

# NOVA ROTA PARA A PÁGINA DE BANIDOS
@app.route('/banned-users')
def banned_users_page():
    if not session.get('admin_logged_in'): return redirect(url_for('admin_login'))
    return render_template('banned_users.html')

# --- API de Gerenciamento de Usuários ---

@app.route('/users', methods=['GET'])
def get_users_api():
    if not session.get('admin_logged_in'): return jsonify({'status': 'erro', 'mensagem': 'Acesso não autorizado'}), 401
    
    query_param = request.args.get('query', '')
    is_banned_filter = request.args.get('banned', 'false').lower() == 'true'
    
    conn, cursor = conectar_banco()
    
    sql = 'SELECT id, username, hwid, expiration_date, is_banned, ban_reason FROM users WHERE is_banned = ?'
    params = [is_banned_filter]

    if query_param:
        sql += ' AND username LIKE ?'
        params.append(f'%{query_param}%')
    
    sql += ' ORDER BY id DESC'
    cursor.execute(sql, tuple(params))
    
    users = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(users), 200

# NOVAS ROTAS PARA BANIR E DESBANIR
@app.route('/admin/users/ban/<int:user_id>', methods=['POST'])
def ban_user(user_id):
    if not session.get('admin_logged_in'): return jsonify({'status': 'erro', 'mensagem': 'Acesso não autorizado'}), 401
    reason = request.json.get('reason', 'Banido manualmente pelo administrador.')
    conn, cursor = conectar_banco()
    cursor.execute('UPDATE users SET is_banned = 1, ban_reason = ? WHERE id = ?', (reason, user_id))
    conn.commit()
    conn.close()
    return jsonify({'status': 'sucesso', 'message': 'Usuário banido com sucesso.'}), 200

@app.route('/admin/users/unban/<int:user_id>', methods=['POST'])
def unban_user(user_id):
    if not session.get('admin_logged_in'): return jsonify({'status': 'erro', 'mensagem': 'Acesso não autorizado'}), 401
    conn, cursor = conectar_banco()
    cursor.execute('UPDATE users SET is_banned = 0, ban_reason = NULL WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    return jsonify({'status': 'sucesso', 'message': 'Banimento anulado com sucesso.'}), 200

# Rota para deletar usuário
@app.route('/admin/users/delete/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    if not session.get('admin_logged_in'): return jsonify({'status': 'erro', 'mensagem': 'Acesso não autorizado'}), 401
    conn, cursor = conectar_banco()
    cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    return jsonify({'status': 'sucesso', 'message': 'Usuário excluído com sucesso'}), 200


# --- APIs do Cliente ---

@app.route('/api/report-violation', methods=['POST'])
def report_violation():
    data = request.get_json()
    hwid = data.get('hwid')
    reason = data.get('reason', 'Violação de segurança não especificada.')
    if not hwid: return jsonify({'status': 'erro', 'mensagem': 'HWID não fornecido.'}), 400
    conn, cursor = conectar_banco()
    cursor.execute('UPDATE users SET is_banned = 1, ban_reason = ? WHERE hwid = ?', (reason, hwid))
    conn.commit()
    conn.close()
    return jsonify({'status': 'sucesso', 'message': 'Violação reportada.'}), 200

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    if not data: return jsonify({'status': 'erro', 'mensagem': 'Dados da requisição ausentes.'}), 400
    
    conn, cursor = conectar_banco()

    # Checagem de versão
    cursor.execute("SELECT value FROM system_settings WHERE key = 'system_version'")
    required_version = (cursor.fetchone() or {}).get('value', '1.0')
    if data.get('client_version') != required_version:
        conn.close()
        return jsonify({'status': 'erro', 'mensagem': f'Versão desatualizada. Use a {required_version}.'}), 426

    # Checagem de login
    cursor.execute('SELECT * FROM users WHERE username = ?', (data['usuario'],))
    user = cursor.fetchone()
    
    if not user:
        conn.close()
        return jsonify({'status': 'erro', 'mensagem': 'Usuário ou senha inválidos.'}), 401

    if user['is_banned']:
        conn.close()
        return jsonify({'status': 'erro', 'mensagem': f"ACESSO BLOQUEADO. Motivo: {user['ban_reason']}"}), 403

    if not bcrypt.checkpw(data['key'].encode('utf-8'), user['password'].encode('utf-8')):
        conn.close()
        return jsonify({'status': 'erro', 'mensagem': 'Usuário ou senha inválidos.'}), 401

    if user['hwid'] and user['hwid'] != data['hwid']:
        conn.close()
        return jsonify({'status': 'erro', 'mensagem': 'Licença vinculada a outro dispositivo.'}), 403
    elif not user['hwid']:
        cursor.execute('UPDATE users SET hwid = ? WHERE username = ?', (data['hwid'], data['usuario']))
        conn.commit()

    conn.close()
    return jsonify({'status': 'sucesso', 'mensagem': 'Login bem-sucedido!'}), 200

# ... (restante do app.py, como a rota /api/system-settings, sem alterações)
@app.route('/api/system-settings', methods=['GET', 'POST'])
def system_settings():
    if request.method == 'POST':
        if not session.get('admin_logged_in'): return jsonify({'status': 'erro', 'mensagem': 'Acesso não autorizado'}), 401
        data = request.get_json()
        conn, cursor = conectar_banco()
        for key, value in data.items():
            cursor.execute('REPLACE INTO system_settings (key, value) VALUES (?, ?)', (key, value))
        conn.commit()
        conn.close()
        return jsonify({'status': 'sucesso', 'message': 'Configurações atualizadas!'}), 200
    
    conn, cursor = conectar_banco()
    cursor.execute('SELECT key, value FROM system_settings')
    settings = {row['key']: row['value'] for row in cursor.fetchall()}
    conn.close()
    return jsonify(settings), 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=True, host='0.0.0.0', port=port)
