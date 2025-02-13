from app import app, db, User
from werkzeug.security import generate_password_hash
from flask_migrate import upgrade

def init_db():
    with app.app_context():
        # Criar tabelas se não existirem
        db.create_all()
        
        # Executa as migrações pendentes
        upgrade()
        
        # Cria o usuário admin se não existir
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
            print("Usuário admin criado com sucesso!")
        
        print("Banco de dados inicializado com sucesso!")

if __name__ == '__main__':
    init_db() 