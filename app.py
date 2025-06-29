from flask import Flask, request, jsonify, render_template, session, redirect, url_for
import sqlite3
import os
from dotenv import load_dotenv
import bcrypt
from datetime import datetime, timedelta, timezone
import traceback # Import para detalhar o erro

load_dotenv()
app = Flask(__name__)
app.secret_key = os.urandom(24)

# --- Funções do Banco de Dados ---

def get_db_path():
    render_disk_path = os.environ.get('RENDER_DISK_PATH', 'instance')
    if not os.path.exists(render_disk_path):
        os.makedirs(render_disk_path)
    return os.path.join(render_disk_path, 'users.db')

def conectar_banco():
    db_path = get_db_path()
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        return conn, conn.cursor()
    except sqlite3.Error as e:
        print(f"Erro ao conectar ao banco de dados: {e}")
        raise

# --- Rotas do Painel de Administração e Autenticação (sem alterações) ---

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        try:
            conn, cursor = conectar_banco()
            cursor.execute('SELECT password FROM admins WHERE username = ?', (username,))
            admin = cursor.fetchone()
            conn.close()
            if admin and bcrypt.checkpw(password.encode('utf-8'), admin['password'].encode('utf-8')):
                session['admin_logged_in'] = True
                return redirect(url_for('gerenciar_usuarios'))
            return render_template('admin_login.html', error='Credenciais inválidas.')
        except Exception as e:
            print(f"ERRO NO LOGIN ADMIN: {e}")
            return render_template('admin_login.html', error='Ocorreu um erro no servidor.')
    return render_template('admin_login.html')

@app.route('/')
def home():
    return redirect(url_for('admin_login'))

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('admin_login'))

# --- Rotas de Navegação do Painel (sem alterações) ---
@app.route('/gerenciar-usuarios')
def gerenciar_usuarios():
    if not session.get('admin_logged_in'): return redirect(url_for('admin_login'))
    return render_template('gerenciar_usuarios.html')

@app.route('/criar-usuario')
def criar_usuario_page():
    if not session.get('admin_logged_in'): return redirect(url_for('admin_login'))
    return render_template('criar_usuario.html')

@app.route('/banned-users')
def banned_users_page():
    if not session.get('admin_logged_in'): return redirect(url_for('admin_login'))
    return render_template('banned_users.html')

@app.route('/configuracoes')
def configuracoes():
    if not session.get('admin_logged_in'): return redirect(url_for('admin_login'))
    return render_template('configuracoes.html')

# --- API de Gerenciamento de Usuários (sem alterações) ---
@app.route('/users', methods=['GET'])
def get_users():
    if not session.get('admin_logged_in'): 
        return jsonify({'status': 'erro', 'mensagem': 'Acesso não autorizado'}), 401
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

@app.route('/admin/users', methods=['POST'])
def create_user():
    if not session.get('admin_logged_in'): 
        return jsonify({'status': 'erro', 'mensagem': 'Acesso não autorizado'}), 401
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    access_days = data.get('access_days')
    if not all([username, password, access_days]):
        return jsonify({'message': 'Todos os campos são obrigatórios.'}), 400
    try:
        days = int(access_days)
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        expiration_date = datetime.now(timezone.utc) + timedelta(days=days)
        conn, cursor = conectar_banco()
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            conn.close()
            return jsonify({'message': 'Este nome de usuário já está em uso.'}), 409
        cursor.execute(
            'INSERT INTO users (username, password, expiration_date, is_banned, ban_reason) VALUES (?, ?, ?, ?, NULL)',
            (username, hashed_password, expiration_date.isoformat(), 0)
        )
        conn.commit()
        conn.close()
        return jsonify({'message': f'Usuário {username} criado com sucesso por {days} dias!'}), 201
    except ValueError:
        return jsonify({'message': 'Os dias de acesso devem ser um número inteiro válido.'}), 400
    except Exception as e:
        print(f"ERRO AO CRIAR USUÁRIO: {e}")
        return jsonify({'message': 'Ocorreu um erro interno no servidor.'}), 500

# Rotas de ban, unban, reset_hwid, delete (sem alterações)
@app.route('/admin/users/ban/<int:user_id>', methods=['POST'])
def ban_user(user_id):
    if not session.get('admin_logged_in'): return jsonify({'status': 'erro', 'mensagem': 'Acesso não autorizado'}), 401
    reason = request.json.get('reason', 'Motivo não especificado.')
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
    return jsonify({'status': 'sucesso', 'message': 'Banimento do usuário anulado com sucesso.'}), 200

@app.route('/users/reset_hwid/<int:user_id>', methods=['POST'])
def reset_hwid(user_id):
    if not session.get('admin_logged_in'): return jsonify({'status': 'erro', 'mensagem': 'Acesso não autorizado'}), 401
    conn, cursor = conectar_banco()
    cursor.execute('UPDATE users SET hwid = NULL WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    return jsonify({'status': 'sucesso', 'message': 'HWID resetado com sucesso'}), 200

@app.route('/admin/users/delete/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    if not session.get('admin_logged_in'): return jsonify({'status': 'erro', 'mensagem': 'Acesso não autorizado'}), 401
    conn, cursor = conectar_banco()
    cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    return jsonify({'status': 'sucesso', 'message': 'Usuário excluído com sucesso'}), 200

# --- APIs do Cliente Externo ---
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
    return jsonify({'status': 'sucesso', 'message': 'Violação reportada com sucesso.'}), 200


# --- ROTA DE LOGIN MODIFICADA PARA DEPURACAO ---
@app.route('/api/login', methods=['POST'])
def api_login():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'erro', 'mensagem': 'Dados da requisição ausentes.'}), 400

        username = data.get('usuario')
        password = data.get('senha')
        hwid = data.get('hwid')
        client_version = data.get('client_version')

        if not all([username, password, hwid, client_version]):
            return jsonify({'status': 'erro', 'mensagem': 'Campos obrigatórios ausentes: usuario, senha, hwid, client_version.'}), 400

        conn, cursor = conectar_banco()

        cursor.execute("SELECT value FROM system_settings WHERE key = 'system_version'")
        required_version = (cursor.fetchone() or {}).get('value', '1.0')
        if client_version != required_version:
            conn.close()
            return jsonify({'status': 'erro', 'mensagem': f'Versão desatualizada. Use a {required_version}.'}), 426

        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        
        if not user:
            conn.close()
            return jsonify({'status': 'erro', 'mensagem': 'Usuário ou senha inválidos.'}), 401

        if user['is_banned']:
            conn.close()
            return jsonify({'status': 'erro', 'mensagem': f"ACESSO BLOQUEADO. Motivo: {user['ban_reason']}"}), 403

        if not user['expiration_date'] or datetime.now(timezone.utc) > datetime.fromisoformat(user['expiration_date']):
             conn.close()
             return jsonify({'status': 'erro', 'mensagem': 'Seu tempo de acesso expirou.'}), 403

        if not user['password'] or not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            conn.close()
            return jsonify({'status': 'erro', 'mensagem': 'Usuário ou senha inválidos.'}), 401

        if user['hwid'] and user['hwid'] != hwid:
            conn.close()
            return jsonify({'status': 'erro', 'mensagem': 'Licença vinculada a outro dispositivo.'}), 403
        elif not user['hwid']:
            cursor.execute('UPDATE users SET hwid = ? WHERE username = ?', (hwid, username))
            conn.commit()

        conn.close()
        return jsonify({
            'status': 'sucesso', 
            'mensagem': 'Login bem-sucedido!',
            'expiration_date': user['expiration_date']
        }), 200

    except Exception as e:
        # --- ALTERAÇÃO IMPORTANTE ---
        # Imprime o erro detalhado no console do servidor
        print("--- ERRO DETALHADO NO /api/login ---")
        traceback.print_exc()
        print("------------------------------------")
        
        # Retorna o erro específico para o cliente para podermos ver
        return jsonify({
            'status': 'erro', 
            'mensagem': f"ERRO INTERNO NO SERVIDOR: {str(e)}"
        }), 500

# Rota de system-settings (sem alterações)
@app.route('/api/system-settings', methods=['GET', 'POST'])
def system_settings():
    if request.method == 'POST':
        if not session.get('admin_logged_in'):
            return jsonify({'status': 'erro', 'mensagem': 'Acesso não autorizado'}), 401
        data = request.get_json()
        conn, cursor = conectar_banco()
        for key, value in data.items():
            cursor.execute('REPLACE INTO system_settings (key, value) VALUES (?, ?)', (key, str(value)))
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