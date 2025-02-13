from flask import Flask, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from functools import wraps
import datetime
from flask_cors import CORS
import os
import shutil
from datetime import datetime
import json

# Configuração para ambiente serverless
IS_VERCEL = os.environ.get('VERCEL')
if IS_VERCEL:
    # Na Vercel, usamos um diretório temporário para o SQLite
    DB_PATH = '/tmp/database.db'
else:
    # Localmente, mantemos o comportamento atual
    DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)
    DB_PATH = os.path.join(DATA_DIR, "database.db")

app = Flask(__name__, static_folder='frontend')
CORS(app)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'sua-chave-secreta-aqui')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_PATH}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class Usuario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome_completo = db.Column(db.String(100), nullable=False)
    cpf = db.Column(db.String(11), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    senha = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'mensagem': 'Token não fornecido'}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            usuario_atual = Usuario.query.filter_by(cpf=data['cpf']).first()
        except:
            return jsonify({'mensagem': 'Token inválido'}), 401

        return f(usuario_atual, *args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'mensagem': 'Token não fornecido'}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            usuario_atual = Usuario.query.filter_by(cpf=data['cpf']).first()
            if not usuario_atual.is_admin:
                return jsonify({'mensagem': 'Acesso negado'}), 403
        except:
            return jsonify({'mensagem': 'Token inválido'}), 401

        return f(usuario_atual, *args, **kwargs)
    return decorated

@app.route('/')
def index():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    if os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/registro', methods=['POST'])
def registro():
    try:
        dados = request.get_json()

        if not all(k in dados for k in ('nome_completo', 'cpf', 'email', 'senha')):
            return jsonify({'mensagem': 'Dados incompletos'}), 400

        if Usuario.query.filter_by(cpf=dados['cpf']).first():
            return jsonify({'mensagem': 'CPF já cadastrado'}), 400

        if Usuario.query.filter_by(email=dados['email']).first():
            return jsonify({'mensagem': 'Email já cadastrado'}), 400

        senha_hash = generate_password_hash(dados['senha'], method='sha256')

        novo_usuario = Usuario(
            nome_completo=dados['nome_completo'],
            cpf=dados['cpf'],
            email=dados['email'],
            senha=senha_hash,
            is_admin=False
        )

        db.session.add(novo_usuario)
        db.session.commit()
        backup_database()  # Criar backup após operação importante

        token = jwt.encode({
            'cpf': novo_usuario.cpf,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, app.config['SECRET_KEY'])

        return jsonify({
            'mensagem': 'Usuário registrado com sucesso',
            'token': token,
            'is_admin': False
        }), 201
    except Exception as e:
        db.session.rollback()
        print(f'Erro no registro: {e}')
        return jsonify({'mensagem': 'Erro interno do servidor'}), 500

@app.route('/login', methods=['POST'])
def login():
    dados = request.get_json()

    if not dados or not dados.get('login') or not dados.get('senha'):
        return jsonify({'mensagem': 'Dados de login inválidos'}), 401

    # Tenta encontrar o usuário por CPF ou email
    usuario = Usuario.query.filter(
        (Usuario.cpf == dados['login']) | 
        (Usuario.email == dados['login'])
    ).first()

    if not usuario or not check_password_hash(usuario.senha, dados['senha']):
        return jsonify({'mensagem': 'Credenciais inválidas'}), 401

    token = jwt.encode({
        'cpf': usuario.cpf,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }, app.config['SECRET_KEY'])

    return jsonify({
        'token': token,
        'is_admin': usuario.is_admin
    })

@app.route('/me', methods=['GET'])
@token_required
def perfil_usuario(usuario_atual):
    return jsonify({
        'nome_completo': usuario_atual.nome_completo,
        'cpf': usuario_atual.cpf,
        'email': usuario_atual.email,
        'is_admin': usuario_atual.is_admin
    })

# Rotas de administrador
@app.route('/admin/usuarios', methods=['GET'])
@admin_required
def listar_usuarios(usuario_atual):
    usuarios = Usuario.query.all()
    return jsonify([{
        'id': u.id,
        'nome_completo': u.nome_completo,
        'cpf': u.cpf,
        'email': u.email,
        'is_admin': u.is_admin
    } for u in usuarios])

@app.route('/admin/usuarios/<int:id>', methods=['DELETE'])
@admin_required
def deletar_usuario(usuario_atual, id):
    try:
        usuario = Usuario.query.get_or_404(id)
        if usuario.id == usuario_atual.id:
            return jsonify({'mensagem': 'Não é possível deletar seu próprio usuário'}), 400
        
        db.session.delete(usuario)
        db.session.commit()
        backup_database()  # Criar backup após deleção
        
        return jsonify({'mensagem': 'Usuário deletado com sucesso'})
    except Exception as e:
        db.session.rollback()
        print(f'Erro ao deletar usuário: {e}')
        return jsonify({'mensagem': 'Erro interno do servidor'}), 500

def criar_admin_padrao():
    try:
        admin = Usuario.query.filter_by(email='admin@admin.admin').first()
        if not admin:
            senha_hash = generate_password_hash('senha123', method='sha256')
            admin = Usuario(
                nome_completo='Administrador',
                cpf='00000000000',
                email='admin@admin.admin',
                senha=senha_hash,
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()
            print('Usuário admin criado com sucesso')
    except Exception as e:
        print(f'Erro ao criar usuário admin: {e}')
        db.session.rollback()

def backup_database():
    """Cria um backup do banco de dados"""
    if not IS_VERCEL:  # Só faz backup em ambiente local
        try:
            db_path = DB_PATH
            if os.path.exists(db_path):
                backup_dir = os.path.join(DATA_DIR, 'backups')
                if not os.path.exists(backup_dir):
                    os.makedirs(backup_dir)
                
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                backup_path = os.path.join(backup_dir, f'database_{timestamp}.db')
                shutil.copy2(db_path, backup_path)
                
                backups = sorted([f for f in os.listdir(backup_dir) if f.startswith('database_')])
                for old_backup in backups[:-5]:
                    os.remove(os.path.join(backup_dir, old_backup))
                    
                print(f'Backup criado: {backup_path}')
        except Exception as e:
            print(f'Erro ao criar backup: {e}')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        criar_admin_padrao()
    
    if not IS_VERCEL:
        backup_database()
        app.run(debug=True, port=5000) 