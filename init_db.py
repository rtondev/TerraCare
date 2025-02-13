from app import app, db, User, hash_password
from flask_migrate import upgrade

def init_db():
    with app.app_context():
        try:
            # Criar tabelas apenas se não existirem
            db.create_all()
            
            # Criar admin apenas se não existir
            admin = User.query.filter_by(email='admin@admin.admin').first()
            if not admin:
                print("Criando usuário admin...")
                admin = User(
                    username='admin',
                    email='admin@admin.admin',
                    password=hash_password('senha123'),
                    is_admin=True,
                    is_prefecture=True,
                    city='Todas'
                )
                db.session.add(admin)
                db.session.commit()
                print("Usuário admin criado com sucesso!")
            else:
                print("Usuário admin já existe")
            
            print("Banco de dados inicializado com sucesso!")
            
        except Exception as e:
            print(f"Erro ao inicializar banco: {str(e)}")
            db.session.rollback()
            raise e

if __name__ == '__main__':
    init_db() 