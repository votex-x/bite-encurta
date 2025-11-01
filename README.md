# 🔗 Bite Encurta - Encurtador de URLs Inteligente

Um encurtador de URLs moderno e completo com sistema de autenticação, painel administrativo, API pública e análise de confiabilidade de links.

## ✨ Funcionalidades

### 🎯 Principais Recursos

- **Encurtamento de URLs Gratuito**: Crie links curtos sem necessidade de cadastro
- **Sistema de Autenticação**: Cadastro e login com email e senha
- **Dashboard Personalizado**: Gerencie todos os seus links em um só lugar
- **API Pública**: Encurte URLs programaticamente via API REST
- **Análise de Confiabilidade**: Sistema automático que classifica links como "Confiável", "Suspeito" ou "Desconhecido"
- **Embeds Inteligentes**: Previews otimizados para redes sociais com ícones e design atrativo
- **Estatísticas Detalhadas**: Acompanhe cliques, IPs e user agents
- **Tokens Premium**: Crie links com aliases personalizados usando tokens
- **Painel Administrativo**: Gerenciamento completo de usuários e tokens

### 🔐 Sistema de Autenticação

- Cadastro com email e senha
- Senhas criptografadas com bcrypt
- Sistema de sessões com Flask-Login
- Acesso ao painel personalizado após login

### 👑 Painel Administrativo

Administradores podem:
- Visualizar estatísticas gerais do sistema
- Gerar tokens para usuários específicos por email
- Promover usuários a administradores
- Gerenciar todos os tokens do sistema

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
- **Flask-Bcrypt**: Criptografia de senhas
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
    ├── index.html         # Página inicial
    ├── login.html         # Página de login
    ├── register.html      # Página de cadastro
    ├── dashboard.html     # Dashboard do usuário
    ├── admin.html         # Painel administrativo
    ├── embed.html         # Preview de links (embeds)
    ├── stats.html         # Estatísticas de cliques
    └── api_docs.html      # Documentação da API
```

## 💾 Banco de Dados

O sistema utiliza SQLite com as seguintes tabelas:

- **users**: Usuários cadastrados
- **urls**: Links encurtados
- **tokens**: Tokens premium para aliases personalizados
- **stats**: Estatísticas de cliques

## 🔑 Funcionalidades por Tipo de Usuário

### Visitante (Não Autenticado)
- Visualizar página inicial
- Acessar documentação da API
- Usar API pública para encurtar URLs

### Usuário Autenticado
- Criar links encurtados
- Gerar tokens premium
- Criar aliases personalizados com tokens
- Visualizar dashboard com seus links
- Acompanhar estatísticas de cliques

### Administrador
- Todas as funcionalidades de usuário
- Acessar painel administrativo
- Gerar tokens para outros usuários por email
- Promover usuários a administradores
- Visualizar estatísticas gerais do sistema

## 🎯 Casos de Uso

### 1. Encurtar URL via Web (Usuário Autenticado)
1. Faça login ou cadastre-se
2. Acesse o dashboard
3. Cole a URL original
4. (Opcional) Use um token para criar alias personalizado
5. Clique em "Encurtar Link"
6. Copie a URL encurtada e compartilhe

### 2. Encurtar URL via API
```python
import requests

url = "https://seu-dominio.com/api/shorten"
data = {
    "url": "https://exemplo.com/artigo-muito-longo",
    "email": "seu@email.com"
}

response = requests.post(url, json=data)
result = response.json()
print(result["short_url"])
```

### 3. Gerar Token Premium
1. Acesse o dashboard
2. Clique em "Gerar Novo Token"
3. Use o token para criar links com alias personalizado

### 4. Administrador: Enviar Token para Usuário
1. Acesse o painel administrativo
2. Digite o email do usuário
3. Clique em "Gerar Token"
4. O token será vinculado ao usuário e aparecerá no dashboard dele

## 🌟 Melhorias Implementadas

Comparado à versão anterior, este projeto agora possui:

✅ **API Pública** - Qualquer pessoa pode encurtar URLs via API fornecendo apenas email  
✅ **Sistema de Autenticação** - Cadastro e login com email e senha  
✅ **Dashboard Personalizado** - Gerenciamento completo de links e tokens  
✅ **Painel Administrativo** - Controle total do sistema para admins  
✅ **Gerenciamento de Tokens por Email** - Admins podem enviar tokens para usuários específicos  
✅ **Análise de Confiabilidade** - Sistema automático de classificação de segurança  
✅ **Embeds Aprimorados** - Design moderno com ícones e status visual de confiabilidade  
✅ **Extração de Metadados** - Título e descrição extraídos automaticamente das URLs  

## 🔒 Segurança

- Senhas criptografadas com bcrypt
- Proteção contra SQL injection (uso de prepared statements)
- Validação de emails
- Sessões seguras com Flask-Login
- Análise automática de URLs suspeitas

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
