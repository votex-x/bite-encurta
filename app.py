import sqlite3
import string
import random
import time
import requests
from bs4 import BeautifulSoup
from flask import Flask, request, redirect, render_template, abort, g, jsonify, session, flash, url_for
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from datetime import datetime
import re

# --- Configuração ---
app = Flask(__name__)
app.secret_key = 'sua-chave-secreta-muito-segura-aqui-' + str(random.randint(1000, 9999))
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

DATABASE = 'shortener.db'
FREE_CODE_LENGTH = 6
ACCESS_CODE_LENGTH = 8

# --- Funções de Banco de Dados ---

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        
        # Tabela de usuários
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_admin INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Tabela urls
        db.execute("""
            CREATE TABLE IF NOT EXISTS urls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                short_code TEXT UNIQUE NOT NULL,
                original_url TEXT NOT NULL,
                custom_alias TEXT,
                token_used TEXT,
                access_code TEXT UNIQUE NOT NULL,
                click_count INTEGER DEFAULT 0,
                user_id INTEGER,
                created_via TEXT DEFAULT 'web',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        
        # Tabela tokens
        db.execute("""
            CREATE TABLE IF NOT EXISTS tokens (
                token_value TEXT PRIMARY KEY,
                token_type TEXT NOT NULL,
                used INTEGER DEFAULT 0,
                user_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        
        # Tabela stats (para cliques)
        db.execute("""
            CREATE TABLE IF NOT EXISTS stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url_id INTEGER NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (url_id) REFERENCES urls(id)
            )
        """)
        
        db.commit()

# Inicializa o banco de dados na primeira execução
with app.app_context():
    init_db()

# --- User Model para Flask-Login ---
class User(UserMixin):
    def __init__(self, id, email, is_admin):
        self.id = id
        self.email = email
        self.is_admin = is_admin

@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    user_row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if user_row:
        return User(user_row['id'], user_row['email'], user_row['is_admin'])
    return None

# --- Funções Auxiliares ---

def generate_random_string(length):
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

def generate_short_code():
    return generate_random_string(FREE_CODE_LENGTH)

def generate_access_code():
    return generate_random_string(ACCESS_CODE_LENGTH)

def is_valid_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def analyze_url_trust(url):
    """
    Analisa a confiabilidade de uma URL
    Retorna: 'confiavel', 'suspeito', ou 'desconhecido'
    """
    try:
        # Lista de domínios confiáveis conhecidos
        trusted_domains = [
            'google.com', 'youtube.com', 'facebook.com', 'twitter.com', 'instagram.com',
            'github.com', 'stackoverflow.com', 'wikipedia.org', 'amazon.com', 'microsoft.com',
            'apple.com', 'linkedin.com', 'reddit.com', 'medium.com', 'netflix.com'
        ]
        
        # Lista de padrões suspeitos
        suspicious_patterns = [
            r'bit\.ly', r'tinyurl', r'goo\.gl', r'ow\.ly',  # Outros encurtadores
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IPs diretos
            r'free.*download', r'win.*prize', r'click.*here',  # Padrões de spam
        ]
        
        domain = url.split('/')[2] if len(url.split('/')) > 2 else url
        
        # Verifica se é domínio confiável
        for trusted in trusted_domains:
            if trusted in domain.lower():
                return 'confiavel'
        
        # Verifica padrões suspeitos
        for pattern in suspicious_patterns:
            if re.search(pattern, url.lower()):
                return 'suspeito'
        
        # Se não for nem confiável nem suspeito, é desconhecido
        return 'desconhecido'
    except:
        return 'desconhecido'

def fetch_url_metadata(url):
    """
    Busca metadados de uma URL (título, descrição)
    """
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        response = requests.get(url, headers=headers, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Tenta pegar o título
        title = None
        if soup.find('meta', property='og:title'):
            title = soup.find('meta', property='og:title').get('content')
        elif soup.find('title'):
            title = soup.find('title').text
        
        # Tenta pegar a descrição
        description = None
        if soup.find('meta', property='og:description'):
            description = soup.find('meta', property='og:description').get('content')
        elif soup.find('meta', attrs={'name': 'description'}):
            description = soup.find('meta', attrs={'name': 'description'}).get('content')
        
        return {
            'title': title or 'Link Encurtado',
            'description': description or f'Redireciona para: {url}'
        }
    except:
        return {
            'title': 'Link Encurtado',
            'description': f'Redireciona para: {url}'
        }

# --- Rotas de Autenticação ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        
        if not email or not password:
            flash('Email e senha são obrigatórios', 'error')
            return render_template('register.html')
        
        if not is_valid_email(email):
            flash('Email inválido', 'error')
            return render_template('register.html')
        
        if len(password) < 6:
            flash('A senha deve ter pelo menos 6 caracteres', 'error')
            return render_template('register.html')
        
        db = get_db()
        
        # Verifica se o email já existe
        if db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone():
            flash('Este email já está cadastrado', 'error')
            return render_template('register.html')
        
        # Cria o usuário
        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        db.execute("INSERT INTO users (email, password_hash) VALUES (?, ?)", (email, password_hash))
        db.commit()
        
        flash('Cadastro realizado com sucesso! Faça login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        
        db = get_db()
        user_row = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        
        if user_row and bcrypt.check_password_hash(user_row['password_hash'], password):
            user = User(user_row['id'], user_row['email'], user_row['is_admin'])
            login_user(user)
            flash('Login realizado com sucesso!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Email ou senha incorretos', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logout realizado com sucesso!', 'success')
    return redirect(url_for('index'))

# --- Rotas Principais ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    
    # Busca links do usuário
    user_links = db.execute("""
        SELECT * FROM urls 
        WHERE user_id = ? 
        ORDER BY created_at DESC
    """, (current_user.id,)).fetchall()
    
    # Busca tokens do usuário
    user_tokens = db.execute("""
        SELECT * FROM tokens 
        WHERE user_id = ? 
        ORDER BY created_at DESC
    """, (current_user.id,)).fetchall()
    
    return render_template('dashboard.html', links=user_links, tokens=user_tokens)

@app.route('/shorten', methods=['POST'])
@login_required
def shorten():
    original_url = request.form['original_url']
    custom_alias = request.form.get('custom_alias', '').strip()
    token = request.form.get('token', '').strip()

    db = get_db()
    short_code = None
    token_used = None

    # 1. Encurtamento Premium (com token e alias personalizado)
    if custom_alias and token:
        # Verifica se o token é válido e pertence ao usuário
        token_row = db.execute("""
            SELECT * FROM tokens 
            WHERE token_value = ? AND used = 0 AND user_id = ?
        """, (token, current_user.id)).fetchone()
        
        if not token_row:
            flash('Token inválido ou já utilizado.', 'error')
            return redirect(url_for('dashboard'))

        # Verifica se o alias personalizado já existe
        if db.execute("SELECT id FROM urls WHERE short_code = ?", (custom_alias,)).fetchone():
            flash(f"O alias '{custom_alias}' já está em uso.", 'error')
            return redirect(url_for('dashboard'))

        short_code = custom_alias
        token_used = token
        
        # Marca o token como usado
        db.execute("UPDATE tokens SET used = 1 WHERE token_value = ?", (token,))
        db.commit()

    # 2. Encurtamento Free (código aleatório)
    elif not custom_alias and not token:
        # Gera um código aleatório único
        while True:
            short_code = generate_short_code()
            if not db.execute("SELECT id FROM urls WHERE short_code = ?", (short_code,)).fetchone():
                break
    
    else:
        flash('Para usar um alias personalizado, você deve fornecer um token válido.', 'error')
        return redirect(url_for('dashboard'))

    # 3. Salva a URL no banco de dados
    if short_code:
        access_code = generate_access_code()
        try:
            db.execute("""
                INSERT INTO urls (short_code, original_url, custom_alias, token_used, access_code, user_id, created_via)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (short_code, original_url, custom_alias if custom_alias else None, token_used, access_code, current_user.id, 'web'))
            db.commit()
            
            flash('Link encurtado com sucesso!', 'success')
            return redirect(url_for('dashboard'))
        except sqlite3.IntegrityError:
            flash('Erro ao gerar código curto. Tente novamente.', 'error')
            return redirect(url_for('dashboard'))

    flash('Ocorreu um erro desconhecido.', 'error')
    return redirect(url_for('dashboard'))

# --- API Pública ---

@app.route('/api/shorten', methods=['POST'])
def api_shorten():
    """
    API Pública para encurtar URLs
    Requer: url (string) e email (string) no JSON
    Retorna: short_url (string)
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'JSON inválido'}), 400
        
        original_url = data.get('url', '').strip()
        email = data.get('email', '').strip()
        
        if not original_url or not email:
            return jsonify({'error': 'URL e email são obrigatórios'}), 400
        
        if not is_valid_email(email):
            return jsonify({'error': 'Email inválido'}), 400
        
        # Valida URL
        if not original_url.startswith(('http://', 'https://')):
            return jsonify({'error': 'URL deve começar com http:// ou https://'}), 400
        
        db = get_db()
        
        # Gera um código aleatório único
        while True:
            short_code = generate_short_code()
            if not db.execute("SELECT id FROM urls WHERE short_code = ?", (short_code,)).fetchone():
                break
        
        access_code = generate_access_code()
        
        # Salva no banco (sem user_id, pois é via API pública)
        db.execute("""
            INSERT INTO urls (short_code, original_url, access_code, created_via)
            VALUES (?, ?, ?, ?)
        """, (short_code, original_url, access_code, 'api'))
        db.commit()
        
        # URL base
        base_url = request.host_url.rstrip('/')
        short_url = f"{base_url}/{short_code}"
        stats_url = f"{base_url}/stats/{access_code}"
        
        return jsonify({
            'success': True,
            'short_url': short_url,
            'stats_url': stats_url,
            'short_code': short_code,
            'email': email
        }), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/docs')
def api_docs():
    """Documentação da API"""
    return render_template('api_docs.html')

# --- Rotas de Redirecionamento ---

@app.route('/<short_code>')
def redirect_to_url(short_code):
    db = get_db()
    url_row = db.execute("SELECT id, original_url FROM urls WHERE short_code = ?", (short_code,)).fetchone()

    if url_row:
        url_id = url_row['id']
        original_url = url_row['original_url']
        ip_address = request.remote_addr
        user_agent = request.headers.get('User-Agent', '')

        # 1. Loga o clique (stats)
        db.execute("INSERT INTO stats (url_id, ip_address, user_agent) VALUES (?, ?, ?)", 
                   (url_id, ip_address, user_agent))
        
        # 2. Atualiza o contador de cliques
        db.execute("UPDATE urls SET click_count = click_count + 1 WHERE id = ?", (url_id,))
        db.commit()

        # 3. Redireciona
        return redirect(original_url)
    
    # 4. Verifica se é um bot (para embed)
    user_agent = request.headers.get('User-Agent', '').lower()
    if any(bot in user_agent for bot in ['bot', 'crawler', 'spider', 'facebookexternalhit', 'twitterbot', 'discordbot']):
        return redirect(f'/embed/{short_code}')

    return abort(404)

@app.route('/stats/<access_code>')
def view_stats(access_code):
    db = get_db()
    url_row = db.execute("SELECT * FROM urls WHERE access_code = ?", (access_code,)).fetchone()

    if url_row:
        url_id = url_row['id']
        
        # Recupera os 10 últimos cliques
        recent_clicks = db.execute("""
            SELECT ip_address, user_agent, timestamp FROM stats 
            WHERE url_id = ? 
            ORDER BY timestamp DESC 
            LIMIT 10
        """, (url_id,)).fetchall()

        stats_data = {
            'short_code': url_row['short_code'],
            'original_url': url_row['original_url'],
            'click_count': url_row['click_count'],
            'created_at': url_row['created_at'],
            'recent_clicks': recent_clicks
        }
        return render_template('stats.html', stats=stats_data)
    
    return abort(404)

@app.route('/embed/<short_code>')
def embed_preview(short_code):
    db = get_db()
    url_row = db.execute("SELECT original_url FROM urls WHERE short_code = ?", (short_code,)).fetchone()

    if url_row:
        original_url = url_row['original_url']
        
        # Busca metadados da URL
        metadata = fetch_url_metadata(original_url)
        
        # Analisa confiabilidade
        trust_status = analyze_url_trust(original_url)
        
        return render_template('embed.html', 
                             title=metadata['title'], 
                             description=metadata['description'], 
                             original_url=original_url,
                             short_code=short_code,
                             trust_status=trust_status)
    
    return abort(404)

# --- Painel Administrativo ---

@app.route('/admin')
@login_required
def admin_panel():
    if not current_user.is_admin:
        flash('Acesso negado. Apenas administradores.', 'error')
        return redirect(url_for('dashboard'))
    
    db = get_db()
    
    # Estatísticas gerais
    total_users = db.execute("SELECT COUNT(*) as count FROM users").fetchone()['count']
    total_links = db.execute("SELECT COUNT(*) as count FROM urls").fetchone()['count']
    total_clicks = db.execute("SELECT SUM(click_count) as total FROM urls").fetchone()['total'] or 0
    total_tokens = db.execute("SELECT COUNT(*) as count FROM tokens").fetchone()['count']
    
    # Lista de usuários
    users = db.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
    
    # Tokens recentes
    recent_tokens = db.execute("""
        SELECT t.*, u.email 
        FROM tokens t 
        LEFT JOIN users u ON t.user_id = u.id 
        ORDER BY t.created_at DESC 
        LIMIT 20
    """).fetchall()
    
    return render_template('admin.html', 
                         total_users=total_users,
                         total_links=total_links,
                         total_clicks=total_clicks,
                         total_tokens=total_tokens,
                         users=users,
                         recent_tokens=recent_tokens)

@app.route('/admin/generate_token', methods=['POST'])
@login_required
def admin_generate_token():
    if not current_user.is_admin:
        return jsonify({'error': 'Acesso negado'}), 403
    
    user_email = request.form.get('user_email', '').strip()
    
    db = get_db()
    
    # Busca o usuário pelo email
    user_row = db.execute("SELECT id FROM users WHERE email = ?", (user_email,)).fetchone()
    
    if not user_row:
        flash(f'Usuário com email {user_email} não encontrado', 'error')
        return redirect(url_for('admin_panel'))
    
    # Gera token
    new_token = generate_random_string(16)
    db.execute("INSERT INTO tokens (token_value, token_type, user_id) VALUES (?, ?, ?)", 
               (new_token, 'premium', user_row['id']))
    db.commit()
    
    flash(f'Token gerado para {user_email}: {new_token}', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/make_admin/<int:user_id>', methods=['POST'])
@login_required
def make_admin(user_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Acesso negado'}), 403
    
    db = get_db()
    db.execute("UPDATE users SET is_admin = 1 WHERE id = ?", (user_id,))
    db.commit()
    
    flash('Usuário promovido a administrador', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/dashboard/generate_token', methods=['POST'])
@login_required
def user_generate_token():
    """Permite que usuários gerem seus próprios tokens"""
    db = get_db()
    
    # Gera token para o usuário atual
    new_token = generate_random_string(16)
    db.execute("INSERT INTO tokens (token_value, token_type, user_id) VALUES (?, ?, ?)", 
               (new_token, 'premium', current_user.id))
    db.commit()
    
    flash(f'Token gerado com sucesso: {new_token}', 'success')
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True)
