import sqlite3
import string
import random
import time
from flask import Flask, request, redirect, render_template, abort, g

# --- Configuração ---
app = Flask(__name__)
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
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # Tabela tokens
        db.execute("""
            CREATE TABLE IF NOT EXISTS tokens (
                token_value TEXT PRIMARY KEY,
                token_type TEXT NOT NULL,
                used INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # Tabela stats (para cliques)
        db.execute("""
            CREATE TABLE IF NOT EXISTS stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url_id INTEGER NOT NULL,
                ip_address TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (url_id) REFERENCES urls(id)
            )
        """)
        db.commit()

# Inicializa o banco de dados na primeira execução
with app.app_context():
    init_db()

# --- Funções Auxiliares ---

def generate_random_string(length):
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

def generate_short_code():
    return generate_random_string(FREE_CODE_LENGTH)

def generate_access_code():
    return generate_random_string(ACCESS_CODE_LENGTH)

# --- Rotas ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/shorten', methods=['POST'])
def shorten():
    original_url = request.form['original_url']
    custom_alias = request.form.get('custom_alias', '').strip()
    token = request.form.get('token', '').strip()

    db = get_db()
    short_code = None
    token_used = None

    # 1. Encurtamento Premium (com token e alias personalizado)
    if custom_alias and token:
        # Verifica se o token é válido e não foi usado
        token_row = db.execute("SELECT * FROM tokens WHERE token_value = ? AND used = 0", (token,)).fetchone()
        if not token_row:
            return render_template('index.html', error="Token inválido ou já utilizado.", original_url=original_url, custom_alias=custom_alias)

        # Verifica se o alias personalizado já existe
        if db.execute("SELECT id FROM urls WHERE short_code = ?", (custom_alias,)).fetchone():
            return render_template('index.html', error=f"O alias '{custom_alias}' já está em uso.", original_url=original_url, custom_alias=custom_alias)

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
        # Caso o usuário forneça alias sem token, ou token sem alias
        return render_template('index.html', error="Para usar um alias personalizado, você deve fornecer um token válido.", original_url=original_url, custom_alias=custom_alias)

    # 3. Salva a URL no banco de dados
    if short_code:
        access_code = generate_access_code()
        try:
            db.execute("""
                INSERT INTO urls (short_code, original_url, custom_alias, token_used, access_code)
                VALUES (?, ?, ?, ?, ?)
            """, (short_code, original_url, custom_alias if custom_alias else None, token_used, access_code))
            db.commit()
            
            # URL base (simulada para o exemplo)
            base_url = request.host_url.rstrip('/')
            short_url = f"{base_url}/{short_code}"
            stats_url = f"{base_url}/stats/{access_code}"
            
            return render_template('index.html', short_url=short_url, stats_url=stats_url)
        except sqlite3.IntegrityError:
            # Raro, mas pode acontecer se o short_code gerado aleatoriamente já existir
            return render_template('index.html', error="Erro ao gerar código curto. Tente novamente.", original_url=original_url)

    return render_template('index.html', error="Ocorreu um erro desconhecido.", original_url=original_url)


@app.route('/<short_code>')
def redirect_to_url(short_code):
    db = get_db()
    url_row = db.execute("SELECT id, original_url FROM urls WHERE short_code = ?", (short_code,)).fetchone()

    if url_row:
        url_id = url_row['id']
        original_url = url_row['original_url']
        ip_address = request.remote_addr

        # 1. Loga o clique (stats)
        db.execute("INSERT INTO stats (url_id, ip_address) VALUES (?, ?)", (url_id, ip_address))
        
        # 2. Atualiza o contador de cliques
        db.execute("UPDATE urls SET click_count = click_count + 1 WHERE id = ?", (url_id,))
        db.commit()

        # 3. Redireciona
        return redirect(original_url)
    
    # 4. Verifica se é um bot (para embed)
    user_agent = request.headers.get('User-Agent', '').lower()
    if any(bot in user_agent for bot in ['bot', 'crawler', 'spider', 'facebookexternalhit', 'twitterbot', 'discordbot']):
        # Se for um bot e a URL não existir, podemos retornar um embed genérico ou 404
        # Neste caso, vamos para a rota de embed com o código, que retornará 404 se não existir
        return redirect(f'/embed/{short_code}')

    return abort(404)


@app.route('/stats/<access_code>')
def view_stats(access_code):
    db = get_db()
    url_row = db.execute("SELECT * FROM urls WHERE access_code = ?", (access_code,)).fetchone()

    if url_row:
        url_id = url_row['id']
        
        # Recupera os 10 últimos cliques (para ter alguma informação de stats)
        recent_clicks = db.execute("""
            SELECT ip_address, timestamp FROM stats 
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
        # Simulação de dados para o embed (título e descrição)
        # Em um app real, faríamos um request para a original_url para extrair o meta
        # Mas para manter simples, usaremos dados estáticos/derivados
        original_url = url_row['original_url']
        title = f"Link Encurtado: {short_code}"
        description = f"Redireciona para: {original_url}"
        
        return render_template('embed.html', title=title, description=description, original_url=original_url)
    
    return abort(404)

# --- Rota para gerar um token de teste (APENAS PARA TESTE/ADMIN) ---
@app.route('/generate_token')
def generate_test_token():
    # Esta rota deve ser removida ou protegida em produção
    # Mas é útil para o teste inicial
    db = get_db()
    new_token = generate_random_string(16)
    db.execute("INSERT INTO tokens (token_value, token_type) VALUES (?, ?)", (new_token, 'premium'))
    db.commit()
    return f"Token de Teste Gerado (1 uso): <b>{new_token}</b>. Remova esta rota em produção."

if __name__ == '__main__':
    app.run(debug=True)
