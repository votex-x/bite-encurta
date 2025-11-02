import sqlite3
import string
import random
import requests
from bs4 import BeautifulSoup
from flask import Flask, request, redirect, render_template, abort, g, jsonify, session, flash, url_for
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from datetime import datetime, timedelta
import re

# --- Configuração ---
app = Flask(__name__)
app.secret_key = 'sua-chave-secreta-muito-segura-aqui-' + str(random.randint(1000, 9999))
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

DATABASE = 'shortener.db'
FREE_CODE_LENGTH = 6
ACCESS_CODE_LENGTH = 8
ADMIN_PASSWORD = 'sakibites' # Senha de administrador para ações sensíveis

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
        # Tabela de usuários (apenas email, sem senha)
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                is_admin INTEGER DEFAULT 0,
                premium_until TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """
        )
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
        """
        )
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
        """
        )
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
        """
        )
        # --- Migração de Schema (Adicionar colunas se não existirem) ---
        try:
            db.execute("SELECT premium_until FROM users LIMIT 1")
        except sqlite3.OperationalError:
            db.execute("ALTER TABLE users ADD COLUMN premium_until TIMESTAMP")
        try:
            db.execute("SELECT user_id, created_via FROM urls LIMIT 1")
        except sqlite3.OperationalError:
            try:
                db.execute("ALTER TABLE urls ADD COLUMN user_id INTEGER")
            except sqlite3.OperationalError:
                pass
            try:
                db.execute("ALTER TABLE urls ADD COLUMN created_via TEXT DEFAULT 'web'")
            except sqlite3.OperationalError:
                pass
        db.commit()

with app.app_context():
    init_db()

# --- User Model para Flask-Login ---
class User(UserMixin):
    def __init__(self, id, email, is_admin, premium_until):
        self.id = id
        self.email = email
        self.is_admin = is_admin
        self.premium_until = premium_until
    @property
    def is_premium(self):
        if self.premium_until:
            try:
                premium_date = datetime.strptime(self.premium_until, '%Y-%m-%d %H:%M:%S')
                return premium_date > datetime.now()
            except ValueError:
                return False
        return False

@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    user_row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if user_row:
        return User(user_row['id'], user_row['email'], user_row['is_admin'], user_row['premium_until'])
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
    try:
        trusted_domains = [
            'google.com', 'youtube.com', 'facebook.com', 'twitter.com', 'instagram.com',
            'github.com', 'stackoverflow.com', 'wikipedia.org', 'amazon.com', 'microsoft.com',
            'apple.com', 'linkedin.com', 'reddit.com', 'medium.com', 'netflix.com'
        ]
        suspicious_patterns = [
            r'bit\.ly', r'tinyurl', r'goo\.gl', r'ow\.ly',  # Outros encurtadores
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IPs diretos
            r'free.*download', r'win.*prize', r'click.*here',  # Padrões de spam
        ]
        domain = url.split('/')[2] if len(url.split('/')) > 2 else url
        for trusted in trusted_domains:
            if trusted in domain.lower():
                return 'confiavel'
        for pattern in suspicious_patterns:
            if re.search(pattern, url.lower()):
                return 'suspeito'
        return 'desconhecido'
    except:
        return 'desconhecido'
def fetch_url_metadata(url):
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        response = requests.get(url, headers=headers, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        title = None
        if soup.find('meta', property='og:title'):
            title = soup.find('meta', property='og:title').get('content')
        elif soup.find('title'):
            title = soup.find('title').text
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

# --- Rotas Principais ---
@app.route('/')
def index():
    return render_template('index.html')

# --- Rotas de Autenticação (Simplificada - Apenas Email) ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        if not email or not is_valid_email(email):
            flash('Email inválido', 'error')
            return render_template('login.html')
        db = get_db()
        user_row = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        # Se o usuário não existe, cria automaticamente (CORRIGIDO)
        if not user_row:
            db.execute(
                "INSERT INTO users (email, is_admin, premium_until) VALUES (?, 0, NULL)",
                (email,)
            )
            db.commit()
            user_row = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        user = load_user(user_row['id'])
        if user.premium_until == '':
            user.premium_until = None
        login_user(user)
        flash('Login realizado com sucesso!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    flash('Você foi desconectado.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    # Busca os links criados pelo usuário logado
    user_links = db.execute(
        "SELECT short_code, original_url, click_count, created_at FROM urls WHERE user_id = ? ORDER BY created_at DESC",
        (current_user.id,)
    ).fetchall()
    
    # Calcula o total de cliques
    total_clicks = sum(link['click_count'] for link in user_links)
    
    # Busca o total de links criados
    total_links = len(user_links)

    return render_template(
        'dashboard.html',
        user_links=user_links,
        total_clicks=total_clicks,
        total_links=total_links
    )

# --- Rotas de Encurtamento ---
@app.route('/shorten', methods=['POST'])
@login_required
def shorten():
    original_url = request.form.get('original_url')
    custom_alias = request.form.get('custom_alias')
    
    if not original_url:
        flash('URL original é obrigatória.', 'error')
        return redirect(url_for('dashboard'))

    # Validação básica de URL
    if not (original_url.startswith('http://') or original_url.startswith('https://')):
        original_url = 'http://' + original_url

    db = get_db()
    short_code = None
    
    if custom_alias:
        # Verifica se o alias personalizado já existe
        existing_url = db.execute("SELECT id FROM urls WHERE short_code = ?", (custom_alias,)).fetchone()
        if existing_url:
            flash('Alias personalizado já está em uso.', 'error')
            return redirect(url_for('dashboard'))
        short_code = custom_alias
    else:
        # Gera um código curto único
        while True:
            short_code = generate_short_code()
            existing_url = db.execute("SELECT id FROM urls WHERE short_code = ?", (short_code,)).fetchone()
            if not existing_url:
                break

    # Gera o código de acesso (para edição/deleção)
    access_code = generate_access_code()

    try:
        db.execute(
            "INSERT INTO urls (short_code, original_url, access_code, user_id, custom_alias) VALUES (?, ?, ?, ?, ?)",
            (short_code, original_url, access_code, current_user.id, custom_alias)
        )
        db.commit()
        flash(f'Link encurtado com sucesso! Seu link: {request.url_root}{short_code}', 'success')
    except sqlite3.IntegrityError:
        flash('Erro ao encurtar o link. Tente novamente.', 'error')
    
    return redirect(url_for('dashboard'))

# --- Rota de Redirecionamento ---
@app.route('/<short_code>')
def redirect_to_url(short_code):
    db = get_db()
    url_row = db.execute("SELECT * FROM urls WHERE short_code = ?", (short_code,)).fetchone()
    
    if url_row:
        # Incrementa o contador de cliques
        db.execute("UPDATE urls SET click_count = click_count + 1 WHERE id = ?", (url_row['id'],))
        
        # Registra o clique na tabela stats
        ip_address = request.remote_addr
        user_agent = request.headers.get('User-Agent')
        db.execute(
            "INSERT INTO stats (url_id, ip_address, user_agent) VALUES (?, ?, ?)",
            (url_row['id'], ip_address, user_agent)
        )
        db.commit()
        
        return redirect(url_row['original_url'])
    else:
        # Se o código curto não for encontrado, retorna 404
        return abort(404)

# --- Rotas de API (Exemplo) ---
@app.route('/api/v1/shorten', methods=['POST'])
def api_shorten():
    data = request.get_json()
    original_url = data.get('url')
    token = data.get('token')
    
    if not original_url or not token:
        return jsonify({'error': 'URL e token são obrigatórios'}), 400

    db = get_db()
    token_row = db.execute("SELECT * FROM tokens WHERE token_value = ? AND used = 0", (token,)).fetchone()
    
    if not token_row:
        return jsonify({'error': 'Token inválido ou já utilizado'}), 401

    # Marca o token como usado
    db.execute("UPDATE tokens SET used = 1 WHERE token_value = ?", (token,))
    
    # Associa o link ao usuário do token, se houver
    user_id = token_row['user_id']
    
    # Lógica de encurtamento (simplificada para a API)
    short_code = generate_short_code()
    access_code = generate_access_code()
    
    try:
        db.execute(
            "INSERT INTO urls (short_code, original_url, access_code, user_id, token_used, created_via) VALUES (?, ?, ?, ?, ?, ?)",
            (short_code, original_url, access_code, user_id, token, 'api')
        )
        db.commit()
        
        return jsonify({
            'short_url': f'{request.url_root}{short_code}',
            'original_url': original_url,
            'access_code': access_code
        }), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Erro interno ao criar o link curto'}), 500

# --- Rotas de Administração (Exemplo) ---
@app.route('/admin/users')
@login_required
def admin_users():
    if not current_user.is_admin:
        flash('Acesso negado.', 'error')
        return redirect(url_for('dashboard'))
    
    db = get_db()
    users = db.execute("SELECT id, email, is_admin, premium_until, created_at FROM users").fetchall()
    
    return render_template('admin_users.html', users=users)

# --- Rotas de Erro ---
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

if __name__ == '__main__':
    app.run(debug=True)