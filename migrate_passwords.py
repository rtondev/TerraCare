from app import app, db, User, hash_password
from werkzeug.security import check_password_hash

def migrate_passwords():
    with app.app_context():
        users = User.query.all()
        for user in users:
            try:
                # Tentar verificar se é uma senha de teste conhecida
                test_passwords = ['senha123', 'password123']
                for test_pass in test_passwords:
                    if check_password_hash(user.password, test_pass):
                        # Atualizar para o novo formato
                        user.password = hash_password(test_pass)
                        print(f"Senha migrada para usuário: {user.email}")
                        break
            except Exception as e:
                print(f"Erro ao migrar senha para {user.email}: {str(e)}")
        
        db.session.commit()
        print("Migração de senhas concluída")

if __name__ == '__main__':
    migrate_passwords() 