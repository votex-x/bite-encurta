# 🔗 Bite Encurta - Encurtador de URLs Inteligente

Um encurtador de URLs moderno e completo com sistema de autenticação simplificada, painel administrativo, API pública e análise de confiabilidade de links.

## ✨ Funcionalidades

### 🎯 Principais Recursos

- **Encurtamento de URLs Gratuito**: Crie links curtos sem necessidade de cadastro ou login.
- **Sistema de Autenticação Simplificada**: Login apenas com email (sem senha).
- **Dashboard Personalizado**: Gerencie todos os seus links em um só lugar.
- **API Pública**: Encurte URLs programaticamente via API REST.
- **Análise de Confiabilidade**: Sistema automático que classifica links como "Confiável", "Suspeito" ou "Desconhecido".
- **Embeds Inteligentes**: Previews otimizados para redes sociais com ícones e design atrativo.
- **Estatísticas Detalhadas**: Acompanhe cliques, IPs e user agents.
- **Tokens Premium**: Crie links com aliases personalizados usando tokens de uso único.
- **Sistema Premium (30 Dias)**: Administrador pode promover usuários a Premium, dando-lhes tokens ilimitados por 30 dias.
- **Painel Administrativo**: Gerenciamento completo de usuários e tokens.

### 🔐 Sistema de Autenticação

- **Login Simples**: Apenas com email. Se o usuário não existe, é criado automaticamente.
- **Login Necessário para**:
    - Criar links com alias personalizado.
    - Acessar o Dashboard.
    - Gerar tokens.

### 👑 Painel Administrativo

Administradores podem:
- Visualizar estatísticas gerais do sistema.
- **Promover Usuários a Premium (30 dias)**: Substitui a geração de tokens por email.
- Promover usuários a administradores.
- Gerenciar todos os tokens do sistema.
- **Ações Sensíveis Protegidas**: As ações de promoção a Premium e Admin exigem a senha `sakibites`.

### 🌐 API Pública

Endpoint: `POST /api/shorten`

**Requisição:**
```json
{
  "url": "https://exemplo.com/url-muito-longa",
  "email": "seu@email.com"
}
```

**Resposta:**
```json
{
  "success": true,
  "short_url": "https://seu-dominio.com/aB3xY9",
  "stats_url": "https://seu-dominio.com/stats/Kj8mN2pQ",
  "short_code": "aB3xY9",
  "email": "seu@email.com"
}
```

### 🛡️ Sistema de Confiabilidade

Todos os links encurtados são analisados automaticamente e classificados em:

- **✅ Confiável**: Domínios conhecidos e confiáveis (Google, YouTube, GitHub, etc.)
- **⚠️ Suspeito**: Padrões suspeitos detectados (outros encurtadores, IPs diretos, spam)
- **❓ Desconhecido**: Sites sem classificação conhecida

### 🎨 Embeds Aprimorados

- Design moderno e atrativo
- Ícones visuais para status de confiabilidade
- Metadados extraídos automaticamente (título, descrição)
- Otimizado para Discord, Twitter, Facebook e outras redes sociais
- Open Graph e Twitter Cards

## 🚀 Instalação

### Requisitos

- Python 3.11+
- pip3

### Passos

1. Clone o repositório:
```bash
git clone https://github.com/votex-x/bite-encurta.git
cd bite-encurta
```

2. Instale as dependências:
```bash
pip3 install -r requirements.txt
```

3. Execute o aplicativo:
```bash
python3 app.py
```

4. Acesse no navegador:
```
http://localhost:5000
```

## 📦 Dependências

- **Flask**: Framework web
- **Flask-Login**: Gerenciamento de sessões de usuário
- **gunicorn**: Servidor WSGI para produção
- **requests**: Requisições HTTP para análise de URLs
- **beautifulsoup4**: Extração de metadados de páginas web

## 🗂️ Estrutura do Projeto

```
bite-encurta/
├── app.py                  # Aplicação principal
├── requirements.txt        # Dependências
├── shortener.db           # Banco de dados SQLite
├── Procfile               # Configuração para deploy
├── README.md              # Documentação
└── templates/             # Templates HTML
    ├── index.html         # Página inicial (encurtamento sem login)
    ├── login.html         # Página de login (apenas email)
    ├── dashboard.html     # Dashboard do usuário
    ├── admin.html         # Painel administrativo
    ├── embed.html         # Preview de links (embeds)
    ├── stats.html         # Estatísticas de cliques
    └── api_docs.html      # Documentação da API
```

## 💾 Banco de Dados

O sistema utiliza SQLite com as seguintes tabelas:

- **users**: Usuários cadastrados (agora com `premium_until`)
- **urls**: Links encurtados
- **tokens**: Tokens premium para aliases personalizados
- **stats**: Estatísticas de cliques

## 🔑 Funcionalidades por Tipo de Usuário

### Visitante (Não Autenticado)
- Encurtar URLs na página inicial
- Acessar documentação da API
- Usar API pública para encurtar URLs

### Usuário Comum (Autenticado)
- Criar links encurtados com código aleatório
- Gerar tokens premium (uso único)
- Criar aliases personalizados com tokens
- Visualizar dashboard com seus links
- Acompanhar estatísticas de cliques

### Usuário Premium (Autenticado)
- Criar links encurtados com código aleatório
- **Criar aliases personalizados SEM usar tokens** (tokens ilimitados)
- Visualizar dashboard com seus links
- Acompanhar estatísticas de cliques

### Administrador
- Todas as funcionalidades de usuário
- Acessar painel administrativo
- **Promover usuários a Premium (30 dias)** (protegido por senha `sakibites`)
- Promover usuários a administradores (protegido por senha `sakibites`)
- Visualizar estatísticas gerais do sistema

## 🎯 Casos de Uso

### 1. Encurtar URL via Web (Sem Login)
1. Acessa a página inicial (`/`)
2. Cola a URL original
3. Clica em "Encurtar Agora"
4. Copia a URL encurtada e compartilha

### 2. Encurtar URL com Alias (Usuário Comum)
1. Faz login com email (`/login`)
2. Acessa o dashboard (`/dashboard`)
3. Gera um token premium
4. Cola a URL, digita o alias e o token
5. Clica em "Encurtar Link Personalizado"

### 3. Encurtar URL com Alias (Usuário Premium)
1. Faz login com email (`/login`)
2. Acessa o dashboard (`/dashboard`)
3. Cola a URL, digita o alias
4. **Não precisa de token**
5. Clica em "Encurtar Link Personalizado"

### 4. Administrador: Promover a Premium
1. Faz login como admin
2. Acessa `/admin`
3. Digita o email do usuário e a senha `sakibites`
4. Clica em "Promover a Premium por 30 Dias"
5. O usuário terá tokens ilimitados por 30 dias

## 📝 Licença

Este projeto é de código aberto e está disponível para uso livre.

## 👨‍💻 Desenvolvimento

Desenvolvido com 💜 para a comunidade.

## 🤝 Contribuindo

Contribuições são bem-vindas! Sinta-se à vontade para abrir issues e pull requests.

## 📞 Suporte

Para dúvidas e suporte, abra uma issue no GitHub.

---

**Bite Encurta** - Encurte, compartilhe e acompanhe seus links com inteligência! 🚀
