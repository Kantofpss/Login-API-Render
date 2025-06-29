from flask import Flask, request, jsonify, render_template, session, redirect, url_for
import sqlite3
import os
from dotenv import load_dotenv
import bcrypt
from datetime import datetime, timedelta, timezone

load_dotenv()
app = Flask(__name__)
app.secret_key = os.urandom(24)

# --- Funções do Banco de Dados ---

def get_db_path():
    """Determina o caminho do banco de dados, priorizando o disco do Render para persistência."""
    # O caminho 'instance' é usado para desenvolvimento local ou como fallback.
    render_disk_path = os.environ.get('RENDER_DISK_PATH', 'instance')
    if not os.path.exists(render_disk_path):
        os.makedirs(render_disk_path)
    return os.path.join(render_disk_path, 'users.db')

def conectar_banco():
    """Conecta ao banco de dados SQLite e configura para retornar dicionários."""
    db_path = get_db_path()
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row  # Permite acessar colunas por nome
        return conn, conn.cursor()
    except sqlite3.Error as e:
        print(f"Erro ao conectar ao banco de dados: {e}")
        # Em um app de produção, logar o erro em um sistema de monitoramento.
        raise

# --- Rotas do Painel de Administração e Autenticação ---

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Página de login para o administrador."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        try:
            conn, cursor = conectar_banco()
            cursor.execute('SELECT password FROM admins WHERE username = ?', (username,))
            admin = cursor.fetchone()
            conn.close()
            
            if admin and bcrypt.checkpw(password.encode('utf-8'), admin['password']):
                session['admin_logged_in'] = True
                return redirect(url_for('gerenciar_usuarios'))
            
            return render_template('admin_login.html', error='Credenciais inválidas.')
        except Exception as e:
            # Mostra um erro genérico para o usuário e loga o erro real no console.
            print(f"ERRO NO LOGIN ADMIN: {e}")
            return render_template('admin_login.html', error='Ocorreu um erro no servidor.')
    return render_template('admin_login.html')

@app.route('/')
def home():
    """Redireciona a rota raiz para a página de login."""
    return redirect(url_for('admin_login'))

@app.route('/admin/logout')
def admin_logout():
    """Faz o logout do administrador."""
    session.pop('admin_logged_in', None)
    return redirect(url_for('admin_login'))

# --- Rotas de Navegação do Painel ---

@app.route('/gerenciar-usuarios')
def gerenciar_usuarios():
    """Página para gerenciar usuários ativos (não-banidos)."""
    if not session.get('admin_logged_in'): return redirect(url_for('admin_login'))
    return render_template('gerenciar_usuarios.html')

@app.route('/criar-usuario')
def criar_usuario_page():
    """Página com o formulário para criar novos usuários."""
    if not session.get('admin_logged_in'): return redirect(url_for('admin_login'))
    return render_template('criar_usuario.html')

@app.route('/banned-users')
def banned_users_page():
    """Página para listar e gerenciar usuários banidos."""
    if not session.get('admin_logged_in'): return redirect(url_for('admin_login'))
    return render_template('banned_users.html')

@app.route('/configuracoes')
def configuracoes():
    """Página de configurações do sistema."""
    if not session.get('admin_logged_in'): return redirect(url_for('admin_login'))
    return render_template('configuracoes.html')

# --- API de Gerenciamento de Usuários (UNIFICADA) ---

@app.route('/users', methods=['GET'])
def get_users():
    """API para buscar usuários. Filtra por nome e/ou status de banimento."""
    if not session.get('admin_logged_in'): 
        return jsonify({'status': 'erro', 'mensagem': 'Acesso não autorizado'}), 401
    
    query_param = request.args.get('query', '')
    # O padrão é 'false', então se o parâmetro 'banned' não for enviado, ele busca usuários não-banidos.
    is_banned_filter = request.args.get('banned', 'false').lower() == 'true'
    
    conn, cursor = conectar_banco()
    
    # A query base filtra por status de banimento
    sql = 'SELECT id, username, hwid, expiration_date, is_banned, ban_reason FROM users WHERE is_banned = ?'
    params = [is_banned_filter]

    # Adiciona a busca por nome se o parâmetro 'query' for fornecido
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
    """API para criar um novo usuário a partir da página 'criar_usuario.html'."""
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

        # Insere o novo usuário com is_banned=0 (não banido) por padrão
        cursor.execute(
            'INSERT INTO users (username, password, expiration_date, is_banned, ban_reason) VALUES (?, ?, ?, 0, NULL)',
            (username, hashed_password, expiration_date.isoformat())
        )
        conn.commit()
        conn.close()
        return jsonify({'message': f'Usuário {username} criado com sucesso por {days} dias!'}), 201
    
    except ValueError:
        return jsonify({'message': 'Os dias de acesso devem ser um número inteiro válido.'}), 400
    except Exception as e:
        print(f"ERRO AO CRIAR USUÁRIO: {e}")
        return jsonify({'message': 'Ocorreu um erro interno no servidor.'}), 500

@app.route('/admin/users/ban/<int:user_id>', methods=['POST'])
def ban_user(user_id):
    """API para banir um usuário."""
    if not session.get('admin_logged_in'): 
        return jsonify({'status': 'erro', 'mensagem': 'Acesso não autorizado'}), 401
    
    reason = request.json.get('reason', 'Motivo não especificado.')
    conn, cursor = conectar_banco()
    cursor.execute('UPDATE users SET is_banned = 1, ban_reason = ? WHERE id = ?', (reason, user_id))
    conn.commit()
    conn.close()
    return jsonify({'status': 'sucesso', 'message': 'Usuário banido com sucesso.'}), 200

@app.route('/admin/users/unban/<int:user_id>', methods=['POST'])
def unban_user(user_id):
    """API para remover o ban de um usuário."""
    if not session.get('admin_logged_in'): 
        return jsonify({'status': 'erro', 'mensagem': 'Acesso não autorizado'}), 401
    
    conn, cursor = conectar_banco()
    cursor.execute('UPDATE users SET is_banned = 0, ban_reason = NULL WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    return jsonify({'status': 'sucesso', 'message': 'Banimento do usuário anulado com sucesso.'}), 200

@app.route('/users/reset_hwid/<int:user_id>', methods=['POST'])
def reset_hwid(user_id):
    """API para resetar o HWID de um usuário."""
    if not session.get('admin_logged_in'): 
        return jsonify({'status': 'erro', 'mensagem': 'Acesso não autorizado'}), 401
    
    conn, cursor = conectar_banco()
    cursor.execute('UPDATE users SET hwid = NULL WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    return jsonify({'status': 'sucesso', 'message': 'HWID resetado com sucesso'}), 200

@app.route('/admin/users/delete/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    """API para excluir um usuário permanentemente."""
    if not session.get('admin_logged_in'): 
        return jsonify({'status': 'erro', 'mensagem': 'Acesso não autorizado'}), 401
    
    conn, cursor = conectar_banco()
    cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    return jsonify({'status': 'sucesso', 'message': 'Usuário excluído com sucesso'}), 200


# --- APIs do Cliente Externo ---

@app.route('/api/report-violation', methods=['POST'])
def report_violation():
    """API chamada pelo cliente para autobanimento ao detectar violações."""
    data = request.get_json()
    hwid = data.get('hwid')
    reason = data.get('reason', 'Violação de segurança não especificada.')
    
    if not hwid: 
        return jsonify({'status': 'erro', 'mensagem': 'HWID não fornecido.'}), 400
    
    conn, cursor = conectar_banco()
    # Encontra o usuário pelo HWID e o bane
    cursor.execute('UPDATE users SET is_banned = 1, ban_reason = ? WHERE hwid = ?', (reason, hwid))
    conn.commit()
    conn.close()
    return jsonify({'status': 'sucesso', 'message': 'Violação reportada com sucesso.'}), 200


@app.route('/api/login', methods=['POST'])
def api_login():
    """API de login para o cliente. Valida versão, banimento, tempo de acesso, senha e HWID."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'erro', 'mensagem': 'Dados da requisição ausentes.'}), 400

        conn, cursor = conectar_banco()

        # 1. Checagem de Versão do Sistema
        cursor.execute("SELECT value FROM system_settings WHERE key = 'system_version'")
        required_version = (cursor.fetchone() or {}).get('value', '1.0')
        if data.get('client_version') != required_version:
            conn.close()
            return jsonify({'status': 'erro', 'mensagem': f'Versão desatualizada. Use a {required_version}.'}), 426

        # 2. Checagem do Usuário
        cursor.execute('SELECT * FROM users WHERE username = ?', (data['usuario'],))
        user = cursor.fetchone()
        
        if not user:
            conn.close()
            return jsonify({'status': 'erro', 'mensagem': 'Usuário ou senha inválidos.'}), 401

        # 3. Checagem de Banimento
        if user['is_banned']:
            conn.close()
            return jsonify({'status': 'erro', 'mensagem': f"ACESSO BLOQUEADO. Motivo: {user['ban_reason']}"}), 403

        # 4. Checagem do Tempo de Acesso
        if not user['expiration_date'] or datetime.now(timezone.utc) > datetime.fromisoformat(user['expiration_date']):
             conn.close()
             return jsonify({'status': 'erro', 'mensagem': 'Seu tempo de acesso expirou.'}), 403

        # 5. Checagem de Senha
        if not bcrypt.checkpw(data['key'].encode('utf-8'), user['password']):
            conn.close()
            return jsonify({'status': 'erro', 'mensagem': 'Usuário ou senha inválidos.'}), 401

        # 6. Checagem e Vínculo de HWID
        if user['hwid'] and user['hwid'] != data['hwid']:
            conn.close()
            return jsonify({'status': 'erro', 'mensagem': 'Licença vinculada a outro dispositivo.'}), 403
        elif not user['hwid']:
            cursor.execute('UPDATE users SET hwid = ? WHERE username = ?', (data['hwid'], data['usuario']))
            conn.commit()

        conn.close()
        return jsonify({'status': 'sucesso', 'mensagem': 'Login bem-sucedido!'}), 200

    except Exception as e:
        print(f"ERRO INESPERADO EM /api/login: {e}")
        return jsonify({'status': 'erro', 'mensagem': 'Ocorreu um erro inesperado no servidor.'}), 500

@app.route('/api/system-settings', methods=['GET', 'POST'])
def system_settings():
    """API para ler e atualizar as configurações do sistema."""
    if request.method == 'POST':
        if not session.get('admin_logged_in'):
            return jsonify({'status': 'erro', 'mensagem': 'Acesso não autorizado'}), 401
        
        data = request.get_json()
        conn, cursor = conectar_banco()
        for key, value in data.items():
            # REPLACE funciona como INSERT OR UPDATE
            cursor.execute('REPLACE INTO system_settings (key, value) VALUES (?, ?)', (key, value))
        conn.commit()
        conn.close()
        return jsonify({'status': 'sucesso', 'message': 'Configurações atualizadas!'}), 200
    
    # Método GET
    conn, cursor = conectar_banco()
    cursor.execute('SELECT key, value FROM system_settings')
    settings = {row['key']: row['value'] for row in cursor.fetchall()}
    conn.close()
    return jsonify(settings), 200


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=True, host='0.0.0.0', port=port)

