import os
import shutil
from app import app, db, criar_admin_padrao

# Configuração do banco de dados na Vercel
VERCEL_DB_PATH = '/tmp/database.db'
VERSIONED_DB_PATH = os.path.join('data', 'versioned_database.db')

# Copiar o banco versionado para o local temporário
if os.path.exists(VERSIONED_DB_PATH):
    shutil.copy2(VERSIONED_DB_PATH, VERCEL_DB_PATH)
else:
    # Se não existir banco versionado, criar um novo
    with app.app_context():
        db.create_all()
        criar_admin_padrao()

# Função para o handler da Vercel
def handler(event, context):
    return app(event, context) 