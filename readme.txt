SISTEMA DE DENÚNCIAS DE TERRENOS ABANDONADOS
==========================================

1. VISÃO GERAL
-------------
Sistema web desenvolvido em Flask para gerenciamento de denúncias de terrenos abandonados.
Permite que cidadãos reportem problemas e que a prefeitura faça o acompanhamento.

2. ARQUIVOS PRINCIPAIS
--------------------
- app.py: Aplicação principal Flask
- .env: Configurações sensíveis (não versionado)
- .env.example: Exemplo de configurações
- vercel.json: Configuração para deploy
- vercel.sh: Script de build
- requirements.txt: Dependências do projeto
- requirements-prod.txt: Dependências de produção

3. CONFIGURAÇÃO DO AMBIENTE
-------------------------
a) Variáveis de Ambiente (.env):
   - FLASK_ENV=development
   - FLASK_APP=app.py
   - SECRET_KEY=chave_secreta
   - DATABASE_URL=mysql+pymysql://user:password@host/database
   - UPLOAD_FOLDER=static/uploads

b) Banco de Dados:
   - MySQL 8.0 ou superior
   - Charset: utf8mb4
   - Collation: utf8mb4_unicode_ci

4. FUNCIONALIDADES
----------------
4.1 Cidadãos:
    - Cadastro/Login
    - Criar denúncias
    - Upload de fotos
    - Marcar localização no mapa
    - Desenhar polígonos
    - Acompanhar status

4.2 Administradores:
    - Gerenciar usuários
    - Moderar denúncias
    - Ver estatísticas
    - Resetar senhas

4.3 Prefeitura:
    - Visualizar denúncias
    - Atualizar status
    - Responder cidadãos
    - Gerar relatórios

5. STATUS DAS DENÚNCIAS
---------------------
- Pendente: Recém-criada
- Em Análise: Em avaliação
- Resolvido: Problema solucionado
- Recorrente: Problema reincidente
- Cancelado: Denúncia cancelada

6. DEPLOY (VERCEL)
----------------
a) Configuração (vercel.json):
   - Runtime: Python 3.9
   - Framework: Flask
   - Build: vercel.sh

b) Variáveis de Ambiente:
   - Configurar na interface da Vercel
   - Usar secrets para dados sensíveis

c) Build Script (vercel.sh):
   - Instala dependências
   - Configura ambiente Python
   - Prepara arquivos estáticos

7. ARQUIVOS IGNORADOS (.gitignore)
-------------------------------
- .env
- venv/
- __pycache__/
- static/uploads/
- *.pyc
- .vercel

8. FORMULÁRIO DE DENÚNCIA (report_form.html)
----------------------------------------
Campos:
- Endereço
- Descrição
- Fotos (múltiplas)
- Mapa interativo
- Ferramentas de desenho
- Status inicial

9. MANUTENÇÃO
-----------
a) Banco de Dados:
   - Backup diário
   - Limpeza de uploads antigos
   - Monitoramento de performance

b) Segurança:
   - Senhas criptografadas
   - Validação de uploads
   - Proteção contra XSS/CSRF
   - Rate limiting

10. REQUISITOS TÉCNICOS
---------------------
- Python 3.8+
- MySQL 8.0+
- Node.js (para Vercel CLI)
- Espaço em disco: 500MB+
- Memória: 1GB+
- Conexão internet estável

11. SUPORTE
----------
- Email: suporte@exemplo.com
- GitHub Issues
- Documentação: /docs
- Wiki: /wiki

12. BACKUPS
----------
- Banco de dados: Diário
- Uploads: Semanal
- Logs: Mensal
- Configurações: Por mudança

13. MONITORAMENTO
---------------
- Logs de acesso
- Erros de aplicação
- Performance do banco
- Uso de recursos
- Uploads pendentes

14. LIMITAÇÕES
------------
- Tamanho máximo de upload: 5MB
- Máximo de fotos por denúncia: 5
- Cache: 1 hora
- Rate limit: 100 req/min
- Sessão: 24 horas

15. PRÓXIMAS ATUALIZAÇÕES
-----------------------
- API REST
- Notificações push
- App mobile
- Integração WhatsApp
- Dashboard avançado

===================
Última atualização: [DATA]
Versão: 1.0.0
=================== 