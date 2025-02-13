from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime, timedelta, timezone
from jose import jwt
from functools import wraps
from geopy.geocoders import Nominatim
import folium
from flask_migrate import Migrate
from json import dumps, loads
from dotenv import load_dotenv
import pymysql

# Registrar o PyMySQL como driver MySQL
pymysql.install_as_MySQLdb()

# Carregar variáveis de ambiente do arquivo .env
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
    'connect_args': {
        'connect_timeout': 10
    }
}

# Adicionar no início do arquivo, junto com outras constantes
REPORT_STATUS = {
    'ANALYSIS': 'Em Análise',
    'IN_PROGRESS': 'Em Andamento', 
    'RESOLVED': 'Resolvido',
    'CANCELLED': 'Cancelado',
    'VERIFICATION': 'Em Verificação',
    'REOPENED': 'Reaberto'
}

# Cores para cada status
STATUS_COLORS = {
    'Em Análise': 'blue',
    'Em Andamento': 'yellow',
    'Resolvido': 'green',
    'Cancelado': 'red',
    'Em Verificação': 'purple',
    'Reaberto': 'orange'
}

# Descrições dos status
STATUS_DESCRIPTIONS = {
    'Em Análise': 'A equipe técnica está analisando as informações e evidências fornecidas.',
    'Em Andamento': 'Medidas estão sendo tomadas para resolver a situação reportada.',
    'Resolvido': 'A denúncia foi atendida e o problema foi resolvido com sucesso.',
    'Cancelado': 'A denúncia foi cancelada por solicitação ou por não atender aos critérios.',
    'Em Verificação': 'Equipe técnica realizando vistoria presencial no local denunciado.',
    'Reaberto': 'Denúncia reaberta para reavaliação ou novas providências.'
}

# Inicializar o SQLAlchemy com retry
class RetryingDBConnection:
    def __init__(self, app):
        self.app = app
        self.retries = 3
        self.db = None

    def connect(self):
        for i in range(self.retries):
            try:
                print(f"Tentativa {i+1} de conectar ao banco...")
                if not self.app.config['SQLALCHEMY_DATABASE_URI']:
                    raise Exception("DATABASE_URL não está configurada")
                    
                self.db = SQLAlchemy()
                self.db.init_app(self.app)
                
                # Testar conexão
                with self.app.app_context():
                    self.db.engine.connect()
                    print("Conexão com o banco estabelecida com sucesso!")
                
                return self.db
            except Exception as e:
                if i == self.retries - 1:  # Última tentativa
                    print(f"Erro fatal na conexão com o banco: {str(e)}")
                    raise e
                print(f"Tentativa {i+1} falhou com erro: {str(e)}")
                print("Tentando novamente em 1 segundo...")
                import time
                time.sleep(1)

db_connection = RetryingDBConnection(app)
db = db_connection.connect()

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Configuração do Flask-Migrate
migrate = Migrate(app, db)

# Modelo do usuário
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_prefecture = db.Column(db.Boolean, default=False)
    city = db.Column(db.String(100))  # Cidade da prefeitura
    latitude = db.Column(db.Float)  # Localização do usuário
    longitude = db.Column(db.Float)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    reports = db.relationship('Report', backref='author', lazy=True)
    comments = db.relationship('Comment', backref='author', lazy=True)

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    address = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    polygon_points = db.Column(db.Text)
    status = db.Column(db.String(20), default='Em Análise')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comments = db.relationship('Comment', backref='report', lazy=True)

    @property
    def polygon_points_list(self):
        if self.polygon_points:
            return loads(self.polygon_points)
        return None

    @polygon_points_list.setter
    def polygon_points_list(self, value):
        if value is not None:
            self.polygon_points = dumps(value)
        else:
            self.polygon_points = None

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    report_id = db.Column(db.Integer, db.ForeignKey('report.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            return jsonify({"error": "Acesso não autorizado"}), 403
        return f(*args, **kwargs)
    return decorated_function

def generate_token(user_id):
    expiration = datetime.utcnow() + timedelta(hours=24)
    return jwt.encode(
        {'user_id': user_id, 'exp': expiration},
        app.config['SECRET_KEY'],
        algorithm='HS256'
    )

def prefecture_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_prefecture:
            return jsonify({"error": "Acesso não autorizado"}), 403
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    try:
        # Calcular estatísticas com tratamento de erro para divisão por zero
        total_reports = Report.query.count()
        resolved_reports = Report.query.filter_by(status='Resolvido').count()
        
        stats = {
            'total_users': User.query.count(),
            'total_reports': total_reports,
            'resolved_reports': resolved_reports,
            'cities_count': db.session.query(User.city).filter(User.city.isnot(None)).distinct().count(),
            'resolution_rate': (resolved_reports / total_reports * 100) if total_reports > 0 else 0
        }
    except Exception as e:
        print(f"Erro ao calcular estatísticas: {str(e)}")
        # Fornecer valores padrão em caso de erro
        stats = {
            'total_users': 0,
            'total_reports': 0,
            'resolved_reports': 0,
            'cities_count': 0,
            'resolution_rate': 0
        }
    
    return render_template('index.html', stats=stats)

@app.route('/login')
def login_page():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

# Constantes para hash de senha
HASH_METHOD = 'pbkdf2:sha256'
HASH_ITERATIONS = 150000

def hash_password(password):
    """Função para padronizar o hash de senha em toda a aplicação"""
    return generate_password_hash(password, method=HASH_METHOD, salt_length=16)

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.form
        print(f"Tentativa de login para email: {data.get('email')}")
        
        user = User.query.filter_by(email=data.get('email')).first()
        if not user:
            print(f"Usuário não encontrado para email: {data.get('email')}")
            return jsonify({'error': 'Credenciais inválidas'}), 401
        
        password = data.get('password')
        print(f"Verificando senha para usuário: {user.username}")
        
        try:
            is_valid = check_password_hash(user.password, password)
            if is_valid:
                print(f"Login bem-sucedido para usuário: {user.username}")
                login_user(user)
                token = generate_token(user.id)
                
                # Se a senha ainda usa o método antigo, atualizar para o novo
                if not user.password.startswith(HASH_METHOD):
                    print(f"Atualizando hash da senha para usuário: {user.username}")
                    user.password = hash_password(password)
                    db.session.commit()
                
                return jsonify({'token': token, 'redirect': url_for('dashboard')})
        except Exception as e:
            print(f"Erro na verificação da senha: {str(e)}")
            # Se falhou na verificação, tentar com senha padrão
            if password == 'senha123' and user.is_admin:
                print("Usando senha padrão para admin")
                user.password = hash_password(password)
                db.session.commit()
                login_user(user)
                token = generate_token(user.id)
                return jsonify({'token': token, 'redirect': url_for('dashboard')})
        
        print(f"Senha incorreta para usuário: {user.username}")
        return jsonify({'error': 'Credenciais inválidas'}), 401
            
    except Exception as e:
        print(f"Erro no login: {str(e)}")
        return jsonify({'error': 'Erro interno do servidor'}), 500

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    
    try:
        data = request.form
        if User.query.filter_by(email=data.get('email')).first():
            return jsonify({'error': 'Email já cadastrado'}), 400
        
        # Usar função padronizada de hash
        password = data.get('password')
        hashed_password = hash_password(password)
        
        # Capturar localização do usuário
        latitude = data.get('latitude')
        longitude = data.get('longitude')
        
        user = User(
            username=data.get('username'),
            email=data.get('email'),
            password=hashed_password,  # Usar o hash padronizado
            latitude=latitude,
            longitude=longitude
        )
        db.session.add(user)
        db.session.commit()
        
        print(f"Usuário registrado com sucesso: {user.email}")
        return jsonify({'message': 'Usuário registrado com sucesso', 'redirect': url_for('login')})
        
    except Exception as e:
        print(f"Erro no registro: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Erro ao registrar usuário'}), 500

@app.route('/me')
@login_required
def me():
    return jsonify({
        'id': current_user.id,
        'username': current_user.username,
        'email': current_user.email,
        'is_admin': current_user.is_admin
    })

@app.route('/admin/users')
@admin_required
def admin_users():
    users = User.query.all()
    return render_template('admin.html', users=users)

@app.route('/admin/user/<int:user_id>', methods=['DELETE'])
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'Usuário deletado com sucesso'})

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    reports = Report.query.order_by(Report.created_at.desc()).all()
    return render_template('home.html', reports=reports)

@app.route('/account')
@login_required
def account():
    return render_template('account.html')

@app.route('/report/new', methods=['GET', 'POST'])
@login_required
def new_report():
    if request.method == 'POST':
        data = request.json
        
        report = Report(
            address=data.get('address'),
            description=data.get('description'),
            latitude=float(data.get('latitude')),
            longitude=float(data.get('longitude')),
            polygon_points_list=data.get('polygon_points'),  # Usar o setter
            user_id=current_user.id
        )
        db.session.add(report)
        db.session.commit()
        return jsonify({'message': 'Denúncia registrada com sucesso'})
    
    return render_template('report_form.html')

@app.route('/reports')
@login_required
def reports():
    reports = Report.query.order_by(Report.created_at.desc()).all()
    return render_template('reports.html', reports=reports)

@app.route('/report/<int:report_id>')
@login_required
def report_detail(report_id):
    report = Report.query.get_or_404(report_id)
    return render_template('report_detail.html', report=report)

@app.route('/report/<int:report_id>/comment', methods=['POST'])
@login_required
def add_comment(report_id):
    report = Report.query.get_or_404(report_id)
    content = request.form.get('content')
    
    comment = Comment(
        content=content,
        user_id=current_user.id,
        report_id=report_id
    )
    db.session.add(comment)
    db.session.commit()
    
    return jsonify({'message': 'Comentário adicionado com sucesso'})

@app.route('/report/<int:report_id>/status', methods=['PUT'])
@prefecture_required
def update_status(report_id):
    report = Report.query.get_or_404(report_id)
    status = request.json.get('status')
    
    if status not in ['Pendente', 'Em Análise', 'Resolvido', 'Cancelado']:
        return jsonify({'error': 'Status inválido'}), 400
    
    report.status = status
    db.session.commit()
    
    return jsonify({'message': 'Status atualizado com sucesso'})

@app.route('/admin/users/<int:user_id>/permissions', methods=['PUT'])
@admin_required
def update_permissions(user_id):
    user = User.query.get_or_404(user_id)
    data = request.json
    
    if 'is_prefecture' in data:
        user.is_prefecture = data['is_prefecture']
        if user.is_prefecture:
            user.city = data.get('city')
        else:
            user.city = None
            
    if 'is_admin' in data:
        user.is_admin = data['is_admin']
    
    db.session.commit()
    return jsonify({'message': 'Permissões atualizadas com sucesso'})

# Adicionar função para serializar Report
def serialize_report(report):
    return {
        'id': report.id,
        'address': report.address,
        'description': report.description,
        'latitude': report.latitude,
        'longitude': report.longitude,
        'status': report.status,
        'created_at': report.created_at.strftime('%Y-%m-%d %H:%M:%S'),
        'polygon_points': report.polygon_points_list,  # Já retorna a lista de pontos
        'author': {
            'id': report.author.id,
            'username': report.author.username
        }
    }

@app.route('/prefecture/reports')
@prefecture_required
def prefecture_reports():
    if current_user.is_admin:
        reports = Report.query.order_by(Report.created_at.desc()).all()
    else:
        reports = Report.query.filter(
            Report.address.like(f'%{current_user.city}%')
        ).order_by(Report.created_at.desc()).all()
    
    # Serializar os reports
    serialized_reports = [serialize_report(report) for report in reports]
    return render_template('prefecture_reports.html', reports=reports, reports_json=serialized_reports)

def init_db():
    with app.app_context():
        try:
            # Criar tabelas se não existirem
            db.create_all()
            
            # Criar admin se não existir
            admin = User.query.filter_by(email='admin@admin.admin').first()
            if not admin:
                admin = User(
                    username='admin',
                    email='admin@admin.admin',
                    password=hash_password('senha123'),  # Usar função padronizada
                    is_admin=True,
                    is_prefecture=True,
                    city='Todas'
                )
                db.session.add(admin)
                db.session.commit()
                print("Admin criado com sucesso!")
                
        except Exception as e:
            print(f"Erro ao inicializar banco: {str(e)}")
            db.session.rollback()
            raise e

@app.errorhandler(500)
def internal_error(error):
    print(f"Erro 500: {str(error)}")
    return jsonify({'error': 'Erro interno do servidor'}), 500

@app.route('/report/<int:id>/status', methods=['POST'])
@login_required
def update_report_status(id):
    report = Report.query.get_or_404(id)
    new_status = request.form.get('status')
    
    if new_status not in REPORT_STATUS.values():
        return jsonify({'error': 'Status inválido'}), 400
        
    report.status = new_status
    db.session.commit()
    
    return jsonify({
        'status': report.status,
        'color': STATUS_COLORS.get(report.status, 'gray'),
        'description': STATUS_DESCRIPTIONS.get(report.status, '')
    })

if __name__ == '__main__':
    # init_db()  # Comentar esta linha para não recriar o banco toda vez
    app.run(debug=True) 