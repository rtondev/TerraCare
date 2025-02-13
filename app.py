from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from config.database import get_db_connection, init_db, backup_db
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY')

# Função para verificar se usuário está logado
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Por favor, faça login para acessar esta página')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Função para verificar se é admin
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or not session.get('is_admin'):
            flash('Acesso negado. Apenas administradores podem acessar esta página.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        conn = get_db_connection()
        if conn:
            try:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
                user = cursor.fetchone()
                
                if user and check_password_hash(user['password'], password):
                    session['user_id'] = user['id']
                    session['email'] = user['email']
                    session['is_admin'] = user['role'] == 'admin'
                    return redirect(url_for('profile'))
                    
                flash('Email ou senha incorretos')
            except Exception as e:
                flash('Erro ao fazer login')
                print(f"Erro no login: {e}")
            finally:
                conn.close()
                
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        conn = get_db_connection()
        if conn:
            try:
                cursor = conn.cursor()
                
                # Verificar se email já existe
                cursor.execute('SELECT id FROM users WHERE email = ?', (email,))
                if cursor.fetchone():
                    flash('Email já cadastrado')
                    return render_template('register.html')
                
                # Criar novo usuário
                hashed_password = generate_password_hash(password)
                cursor.execute('''
                    INSERT INTO users (email, password, role)
                    VALUES (?, ?, ?)
                ''', (email, hashed_password, 'user'))
                
                conn.commit()
                flash('Registro realizado com sucesso! Faça login.')
                return redirect(url_for('login'))
                
            except Exception as e:
                flash('Erro ao registrar usuário')
                print(f"Erro no registro: {e}")
            finally:
                conn.close()
                
    return render_template('register.html')

@app.route('/profile')
@login_required
def profile():
    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
            user = cursor.fetchone()
            return render_template('profile.html', user=user)
        finally:
            conn.close()
    
    return redirect(url_for('login'))

@app.route('/admin/users')
@admin_required
def admin_users():
    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users ORDER BY created_at DESC')
            users = cursor.fetchall()
            return render_template('admin/users.html', users=users)
        finally:
            conn.close()
    
    return redirect(url_for('profile'))

@app.route('/admin/backup')
@admin_required
def create_backup():
    backup_db()
    flash('Backup criado com sucesso!')
    return redirect(url_for('admin_users'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
else:
    # Quando rodando na Vercel
    init_db() 