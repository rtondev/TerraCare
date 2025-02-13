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

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'sua_chave_secreta_aqui')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'mysql+pymysql://sql5762446:ifHH5F6xhx@sql5.freesqldatabase.com:3306/sql5762446')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Inicializar o SQLAlchemy com retry
class RetryingDBConnection:
    def __init__(self, app):
        self.app = app
        self.retries = 3
        self.db = None

    def connect(self):
        for i in range(self.retries):
            try:
                self.db = SQLAlchemy(self.app)
                return self.db
            except Exception as e:
                if i == self.retries - 1:  # Última tentativa
                    raise e
                print(f"Tentativa {i+1} de conexão com o banco falhou. Tentando novamente...")
                import time
                time.sleep(1)  # Espera 1 segundo antes de tentar novamente

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
    status = db.Column(db.String(20), default='Pendente')
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
    return render_template('index.html')

@app.route('/login')
def login_page():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    data = request.form
    user = User.query.filter_by(email=data.get('email')).first()
    
    if user and check_password_hash(user.password, data.get('password')):
        login_user(user)
        token = generate_token(user.id)
        return jsonify({'token': token, 'redirect': url_for('dashboard')})
    
    return jsonify({'error': 'Credenciais inválidas'}), 401

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    
    data = request.form
    if User.query.filter_by(email=data.get('email')).first():
        return jsonify({'error': 'Email já cadastrado'}), 400
    
    # Capturar localização do usuário
    latitude = data.get('latitude')
    longitude = data.get('longitude')
    
    user = User(
        username=data.get('username'),
        email=data.get('email'),
        password=generate_password_hash(data.get('password')),
        latitude=latitude,
        longitude=longitude
    )
    db.session.add(user)
    db.session.commit()
    
    return jsonify({'message': 'Usuário registrado com sucesso', 'redirect': url_for('login')})

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
        # Criar tabelas se não existirem
        db.create_all()
        
        # Criar admin se não existir
        admin = User.query.filter_by(email='admin@admin.admin').first()
        if not admin:
            admin = User(
                username='admin',
                email='admin@admin.admin',
                password=generate_password_hash('senha123'),
                is_admin=True,
                is_prefecture=True,
                city='Todas'
            )
            db.session.add(admin)
            db.session.commit()
            print("Admin criado com sucesso!")

if __name__ == '__main__':
    # init_db()  # Comentar esta linha para não recriar o banco toda vez
    app.run(debug=True) 