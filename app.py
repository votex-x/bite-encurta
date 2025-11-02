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
ADMIN_PASSWORD = 'sakibites'

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
                is_admin INTEGER DEFAULT 0,
                premium_until TIMESTAMP,
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
        # Tabela stats
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
        
        # Migração de schema com tratamento de erro melhorado
        columns_to_add = [
            ('users', 'premium_until', 'TIMESTAMP'),
            ('urls', 'user_id', 'INTEGER'),
            ('urls', 'created_via', 'TEXT DEFAULT "web"')
        ]
        
        for table, column, column_type in columns_to_add:
            try:
                db.execute(f"SELECT {column} FROM {table} LIMIT 1")
            except sqlite3.OperationalError:
                try:
                    db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {column_type}")
                    print(f"Coluna {column} adicionada à tabela {table}")
                except sqlite3.OperationalError as e:
                    print(f"Erro ao adicionar coluna {column}: {e}")
        
        db.commit()

# Inicializar banco de dados
with app.app_context():
    init_db()

# --- User Model para Flask-Login ---
class User(UserMixin):
    def __init__(self, id, email, is_admin, premium_until):
        self.id = id
        self.email = email
        self.is_admin = bool(is_admin) if is_admin is not None else False
        self.premium_until = premium_until
    
    @property
    def is_premium(self):
        if not self.premium_until:
            return False
        try:
            if isinstance(self.premium_until, str):
                premium_date = datetime.strptime(self.premium_until, '%Y-%m-%d %H:%M:%S')
            else:
                premium_date = datetime.fromisoformat(self.premium_until)
            return premium_date > datetime.now()
        except (ValueError, TypeError):
            return False

@login_manager.user_loader
def load_user(user_id):
    try:
        db = get_db()
        user_row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if user_row:
            return User(
                user_row['id'], 
                user_row['email'], 
                user_row['is_admin'], 
                user_row['premium_until']
            )
        return None
    except Exception as e:
        print(f"Erro ao carregar usuário: {e}")
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
    if not email:
        return False
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

# --- Rotas Principais ---
@app.route('/')
def index():
    return render_template('index.html')

# --- Rotas de Autenticação ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        if not email or not is_valid_email(email):
            flash('Email inválido', 'error')
            return render_template('login.html')
        
        try:
            db = get_db()
            user_row = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
            
            if not user_row:
                db.execute(
                    "INSERT INTO users (email, is_admin, premium_until) VALUES (?, 0, NULL)",
                    (email,)
                )
                db.commit()
                user_row = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
            
            user = load_user(user_row['id'])
            if user:
                login_user(user)
                flash('Login realizado com sucesso!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Erro ao carregar usuário', 'error')
                
        except Exception as e:
            print(f"Erro no login: {e}")
            flash('Erro interno no servidor', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    flash('Você foi desconectado.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        db = get_db()
        user_links = db.execute(
            "SELECT short_code, original_url, click_count, created_at FROM urls WHERE user_id = ? ORDER BY created_at DESC",
            (current_user.id,)
        ).fetchall()
        
        total_clicks = sum(link['click_count'] for link in user_links)
        total_links = len(user_links)

        return render_template(
            'dashboard.html',
            user_links=user_links,
            total_clicks=total_clicks,
            total_links=total_links
        )
    except Exception as e:
        print(f"Erro no dashboard: {e}")
        flash('Erro ao carregar dashboard', 'error')
        return redirect(url_for('index'))

# --- Rotas de Encurtamento ---
@app.route('/shorten', methods=['POST'])
@login_required
def shorten():
    original_url = request.form.get('original_url', '').strip()
    custom_alias = request.form.get('custom_alias', '').strip()
    
    if not original_url:
        flash('URL original é obrigatória.', 'error')
        return redirect(url_for('dashboard'))

    if not (original_url.startswith('http://') or original_url.startswith('https://')):
        original_url = 'https://' + original_url

    try:
        db = get_db()
        short_code = None
        
        if custom_alias:
            existing_url = db.execute("SELECT id FROM urls WHERE short_code = ?", (custom_alias,)).fetchone()
            if existing_url:
                flash('Alias personalizado já está em uso.', 'error')
                return redirect(url_for('dashboard'))
            short_code = custom_alias
        else:
            while True:
                short_code = generate_short_code()
                existing_url = db.execute("SELECT id FROM urls WHERE short_code = ?", (short_code,)).fetchone()
                if not existing_url:
                    break

        access_code = generate_access_code()

        db.execute(
            "INSERT INTO urls (short_code, original_url, access_code, user_id, custom_alias) VALUES (?, ?, ?, ?, ?)",
            (short_code, original_url, access_code, current_user.id, custom_alias if custom_alias else None)
        )
        db.commit()
        flash(f'Link encurtado com sucesso! Seu link: {request.host_url}{short_code}', 'success')
        
    except sqlite3.IntegrityError as e:
        print(f"Erro de integridade: {e}")
        flash('Erro ao encurtar o link. Tente novamente.', 'error')
    except Exception as e:
        print(f"Erro geral no encurtamento: {e}")
        flash('Erro interno ao encurtar o link.', 'error')
    
    return redirect(url_for('dashboard'))

# --- Rota de Redirecionamento ---
@app.route('/<short_code>')
def redirect_to_url(short_code):
    try:
        db = get_db()
        url_row = db.execute("SELECT * FROM urls WHERE short_code = ?", (short_code,)).fetchone()
        
        if url_row:
            db.execute("UPDATE urls SET click_count = click_count + 1 WHERE id = ?", (url_row['id'],))
            
            ip_address = request.remote_addr
            user_agent = request.headers.get('User-Agent', '')
            db.execute(
                "INSERT INTO stats (url_id, ip_address, user_agent) VALUES (?, ?, ?)",
                (url_row['id'], ip_address, user_agent)
            )
            db.commit()
            
            return redirect(url_row['original_url'])
        else:
            return abort(404)
    except Exception as e:
        print(f"Erro no redirecionamento: {e}")
        return abort(500)

# --- Rotas de API ---
@app.route('/api/v1/shorten', methods=['POST'])
def api_shorten():
    try:
        if not request.is_json:
            return jsonify({'error': 'Content-Type deve ser application/json'}), 400
            
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Dados JSON inválidos'}), 400
            
        original_url = data.get('url')
        token = data.get('token')
        
        if not original_url or not token:
            return jsonify({'error': 'URL e token são obrigatórios'}), 400

        db = get_db()
        token_row = db.execute("SELECT * FROM tokens WHERE token_value = ? AND used = 0", (token,)).fetchone()
        
        if not token_row:
            return jsonify({'error': 'Token inválido ou já utilizado'}), 401

        db.execute("UPDATE tokens SET used = 1 WHERE token_value = ?", (token,))
        
        user_id = token_row['user_id']
        short_code = generate_short_code()
        access_code = generate_access_code()
        
        db.execute(
            "INSERT INTO urls (short_code, original_url, access_code, user_id, token_used, created_via) VALUES (?, ?, ?, ?, ?, ?)",
            (short_code, original_url, access_code, user_id, token, 'api')
        )
        db.commit()
        
        return jsonify({
            'short_url': f'{request.host_url}{short_code}',
            'original_url': original_url,
            'access_code': access_code
        }), 201
        
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Erro ao criar link curto - código já existe'}), 500
    except Exception as e:
        print(f"Erro na API: {e}")
        return jsonify({'error': 'Erro interno do servidor'}), 500

# --- Rotas de Administração ---
@app.route('/admin/users')
@login_required
def admin_users():
    if not current_user.is_admin:
        flash('Acesso negado.', 'error')
        return redirect(url_for('dashboard'))
    
    try:
        db = get_db()
        users = db.execute("SELECT id, email, is_admin, premium_until, created_at FROM users").fetchall()
        return render_template('admin_users.html', users=users)
    except Exception as e:
        print(f"Erro na admin: {e}")
        flash('Erro ao carregar usuários', 'error')
        return redirect(url_for('dashboard'))

# --- Rotas de Erro ---
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(debug=True)
