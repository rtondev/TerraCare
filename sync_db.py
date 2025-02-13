from app import app, db, User
from werkzeug.security import generate_password_hash
from flask_migrate import upgrade
from migrations.add_new_status import upgrade as update_status

def sync_db():
    with app.app_context():
        try:
            # Executar migrações pendentes
            upgrade()
            
            # Verificar/criar usuário admin
            admin = User.query.filter_by(email='admin@admin.admin').first()
            if not admin:
                print("Criando usuário admin...")
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
            else:
                print("Usuário admin já existe")
                
            # Atualizar status
            update_status()
            
            print("Banco de dados sincronizado com sucesso!")
            
        except Exception as e:
            print(f"Erro ao sincronizar banco de dados: {str(e)}")
            raise e

if __name__ == '__main__':
    sync_db() 