import sqlite3
from sqlite3 import Error
from dotenv import load_dotenv
import os
from werkzeug.security import generate_password_hash
from pathlib import Path

load_dotenv()

def ensure_db_directory():
    """Garante que o diretório do banco de dados existe"""
    db_path = Path(os.getenv('DATABASE_PATH'))
    db_dir = db_path.parent
    db_dir.mkdir(parents=True, exist_ok=True)
    return str(db_path)

def get_db_connection():
    try:
        # Garantir que o diretório existe e pegar o caminho completo
        db_path = ensure_db_directory()
        
        # Conectar ao banco de dados
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        
        # Configurar para esperar até 10 segundos se o banco estiver bloqueado
        conn.execute('PRAGMA busy_timeout = 10000')
        # Garantir que as transações são seguras
        conn.execute('PRAGMA journal_mode = WAL')
        
        return conn
    except Error as e:
        print(f"Erro ao conectar ao SQLite: {e}")
        return None

def init_db():
    """Inicializa o banco de dados com as tabelas necessárias"""
    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor()
            
            # Criar tabela de usuários com índices
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    role TEXT CHECK(role IN ('admin', 'user')) DEFAULT 'user',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP
                )
            ''')
            
            # Criar índices para melhor performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_role ON users(role)')
            
            # Verificar se existe admin
            cursor.execute("SELECT * FROM users WHERE email = 'admin@admin.admin'")
            admin = cursor.fetchone()
            
            if not admin:
                # Criar usuário admin padrão
                admin_password = generate_password_hash('senha123')
                cursor.execute('''
                    INSERT INTO users (email, password, role)
                    VALUES (?, ?, ?)
                ''', ('admin@admin.admin', admin_password, 'admin'))
            
            conn.commit()
            print(f"Banco de dados inicializado com sucesso em: {os.getenv('DATABASE_PATH')}")
            
        except Error as e:
            print(f"Erro ao inicializar banco de dados: {e}")
        finally:
            conn.close()

def backup_db():
    """Cria um backup do banco de dados"""
    try:
        db_path = Path(os.getenv('DATABASE_PATH'))
        backup_path = db_path.parent / f"backup_{db_path.name}"
        
        conn = get_db_connection()
        if conn:
            backup = sqlite3.connect(str(backup_path))
            conn.backup(backup)
            backup.close()
            conn.close()
            print(f"Backup criado com sucesso em: {backup_path}")
    except Error as e:
        print(f"Erro ao criar backup: {e}") 