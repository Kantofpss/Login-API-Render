from flask import Flask, request, jsonify, render_template, session, redirect, url_for
import sqlite3
import os
from dotenv import load_dotenv
import bcrypt
import pyotp
from datetime import datetime, timedelta, timezone

load_dotenv()
app = Flask(__name__)
app.secret_key = os.urandom(24)

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

def conectar_banco():
    """Conecta ao banco de dados SQLite."""
    db_path = get_db_path()
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        return conn, conn.cursor()
    except sqlite3.Error as e:
        print(f"Erro ao conectar ao banco de dados: {e}")
        raise

# --- Rotas do Painel de Administração ---
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
            return render_template('admin_login.html', error=f'Erro no servidor: {e}')
    return render_template('admin_login.html')

@app.route('/')
def home():
    return redirect(url_for('admin_login'))

@app.route('/admin/dashboard')
def dashboard():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    return redirect(url_for('gerenciar_usuarios'))
    
@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('admin_login'))

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

# --- API para Gerenciamento de Usuários (com sistema de tempo) ---
@app.route('/users', methods=['GET'])
def get_users():
    if not session.get('admin_logged_in'):
        return jsonify({'status': 'erro', 'mensagem': 'Acesso não autorizado'}), 401
    
    query = request.args.get('query', '')
    conn, cursor = conectar_banco()

    if query:
        cursor.execute('SELECT id, username, hwid, expiration_date FROM users WHERE username LIKE ? ORDER BY id DESC', ('%' + query + '%',))
    else:
        cursor.execute('SELECT id, username, hwid, expiration_date FROM users ORDER BY id DESC')
    
    users = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(users), 200

@app.route('/admin/users', methods=['POST'])
def add_user():
    if not session.get('admin_logged_in'):
        return jsonify({'status': 'erro', 'mensagem': 'Acesso não autorizado'}), 401
    
    data = request.get_json()
    username, password, access_days = data.get('username'), data.get('password'), data.get('access_days')

    if not all([username, password, access_days]):
        return jsonify({'status': 'erro', 'mensagem': 'Todos os campos são obrigatórios.'}), 400
    
    try:
        days = int(access_days)
        if days <= 0: raise ValueError()
        expiration_date = datetime.now(timezone.utc) + timedelta(days=days)
    except (ValueError, TypeError):
        return jsonify({'status': 'erro', 'mensagem': 'A quantidade de dias deve ser um número positivo.'}), 400

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    try:
        conn, cursor = conectar_banco()
        cursor.execute('INSERT INTO users (username, password, expiration_date) VALUES (?, ?, ?)', (username, hashed_password, expiration_date.isoformat()))
        conn.commit()
        conn.close()
        return jsonify({'status': 'sucesso', 'message': f'Usuário {username} criado com {days} dias de acesso.'}), 201
    except sqlite3.IntegrityError:
        return jsonify({'status': 'erro', 'mensagem': 'Este nome de usuário já está em uso.'}), 409
    except Exception as e:
        return jsonify({'status': 'erro', 'mensagem': f'Erro interno: {e}'}), 500

@app.route('/users/extend_access/<int:user_id>', methods=['POST'])
def extend_access(user_id):
    if not session.get('admin_logged_in'):
        return jsonify({'status': 'erro', 'mensagem': 'Acesso não autorizado'}), 401

    try:
        days_to_add = int(request.json.get('days_to_add'))
        if days_to_add <= 0: raise ValueError()
    except (ValueError, TypeError):
        return jsonify({'status': 'erro', 'mensagem': 'Número de dias inválido.'}), 400

    conn, cursor = conectar_banco()
    cursor.execute('SELECT expiration_date FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()

    if not user:
        conn.close()
        return jsonify({'status': 'erro', 'mensagem': 'Usuário não encontrado.'}), 404
    
    now = datetime.now(timezone.utc)
    current_expiration = datetime.fromisoformat(user['expiration_date']) if user['expiration_date'] else now
    start_date = max(now, current_expiration)
    new_expiration_date = start_date + timedelta(days=days_to_add)
    
    cursor.execute('UPDATE users SET expiration_date = ? WHERE id = ?', (new_expiration_date.isoformat(), user_id))
    conn.commit()
    conn.close()
    
    return jsonify({'status': 'sucesso', 'message': f'Acesso estendido por {days_to_add} dias.'}), 200

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

# --- API de Login do Cliente (com verificação de tempo e versão) ---
@app.route('/api/login', methods=['POST'])
def api_login():
    """Valida o login do cliente, incluindo a verificação da versão e data de expiração."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'erro', 'mensagem': 'Dados da requisição ausentes.'}), 400

        conn, cursor = conectar_banco()

        # --- NOVA VERIFICAÇÃO DE VERSÃO NO SERVIDOR ---
        cursor.execute("SELECT value FROM system_settings WHERE key = 'system_version'")
        setting = cursor.fetchone()
        required_version = setting['value'] if setting else None

        if not required_version:
            conn.close()
            return jsonify({'status': 'erro', 'mensagem': 'A versão do sistema não está configurada no servidor.'}), 503

        client_version = data.get('client_version')
        if client_version != required_version:
            conn.close()
            return jsonify({
                'status': 'erro', 
                'mensagem': f'Sua versão ({client_version or "N/A"}) está desatualizada. Por favor, use a versão {required_version}.'
            }), 426 # HTTP 426 Upgrade Required
        # --- FIM DA VERIFICAÇÃO DE VERSÃO ---

        if not all(k in data for k in ['usuario', 'key', 'hwid']):
            conn.close()
            return jsonify({'status': 'erro', 'mensagem': 'Dados da requisição incompletos.'}), 400

        cursor.execute('SELECT password, hwid, expiration_date FROM users WHERE username = ?', (data['usuario'],))
        user = cursor.fetchone()
        
        if not user:
            conn.close()
            return jsonify({'status': 'erro', 'mensagem': 'Usuário ou senha inválidos.'}), 404

        if not user['expiration_date']:
            conn.close()
            return jsonify({'status': 'erro', 'mensagem': 'Sua conta não possui uma licença ativa. Contate o suporte.'}), 403

        expiration_time = datetime.fromisoformat(user['expiration_date'])
        if datetime.now(timezone.utc) > expiration_time:
            conn.close()
            return jsonify({'status': 'erro', 'mensagem': 'Seu tempo de acesso esgotou.'}), 403

        if not bcrypt.checkpw(data['key'].encode('utf-8'), user['password'].encode('utf-8')):
            conn.close()
            return jsonify({'status': 'erro', 'mensagem': 'Usuário ou senha inválidos.'}), 401

        if user['hwid'] and user['hwid'] != data['hwid']:
            conn.close()
            return jsonify({'status': 'erro', 'mensagem': 'Acesso negado. A licença está vinculada a outro dispositivo.'}), 403
        elif not user['hwid']:
            cursor.execute('UPDATE users SET hwid = ? WHERE username = ?', (data['hwid'], data['usuario']))
            conn.commit()

        conn.close()
        return jsonify({'status': 'sucesso', 'mensagem': 'Login bem-sucedido!'}), 200
    
    except Exception as e:
        # Garante que a conexão seja fechada em caso de erro
        if 'conn' in locals() and conn:
            conn.close()
        print(f"ERRO INESPERADO EM /api/login: {e}")
        return jsonify({'status': 'erro', 'mensagem': 'Ocorreu um erro inesperado no servidor.'}), 500

# API PARA CONFIGURAÇÕES DO SISTEMA
@app.route('/api/system-settings', methods=['GET', 'POST'])
def system_settings():
    if request.method == 'POST':
        if not session.get('admin_logged_in'):
            return jsonify({'status': 'erro', 'mensagem': 'Acesso não autorizado'}), 401
        
        try:
            conn, cursor = conectar_banco()
            data = request.get_json()
            if not data:
                conn.close()
                return jsonify({'status': 'erro', 'mensagem': 'Nenhum dado enviado.'}), 400
            
            for key, value in data.items():
                cursor.execute('UPDATE system_settings SET value = ? WHERE key = ?', (value, key))
            conn.commit()
            conn.close()
            return jsonify({'status': 'sucesso', 'message': 'Configurações atualizadas com sucesso!'}), 200
        except Exception as e:
            if 'conn' in locals() and conn: conn.close()
            return jsonify({'status': 'erro', 'mensagem': f'Erro ao atualizar configurações: {e}'}), 500

    if request.method == 'GET':
        try:
            conn, cursor = conectar_banco()
            cursor.execute('SELECT key, value FROM system_settings')
            settings = {row['key']: row['value'] for row in cursor.fetchall()}
            conn.close()
            return jsonify(settings), 200
        except Exception as e:
            if 'conn' in locals() and conn: conn.close()
            return jsonify({'status': 'erro', 'mensagem': f'Erro ao buscar configurações: {e}'}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=True, host='0.0.0.0', port=port)
