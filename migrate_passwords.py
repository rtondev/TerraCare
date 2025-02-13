from app import app, db, User, hash_password
from werkzeug.security import check_password_hash

def migrate_passwords():
    with app.app_context():
        users = User.query.all()
        for user in users:
            try:
                # Se a senha não usa o método correto, resetar para uma senha padrão
                if not user.password.startswith('pbkdf2:sha256'):
                    default_password = 'senha123'
                    user.password = hash_password(default_password)
                    print(f"Senha resetada para usuário: {user.email}")
            except Exception as e:
                print(f"Erro ao migrar senha para {user.email}: {str(e)}")
        
        db.session.commit()
        print("Migração de senhas concluída")

if __name__ == '__main__':
    migrate_passwords() 