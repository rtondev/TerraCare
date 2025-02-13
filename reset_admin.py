from app import app, db, User, hash_password

def reset_admin():
    with app.app_context():
        try:
            admin = User.query.filter_by(email='admin@admin.admin').first()
            if admin:
                admin.password = hash_password('senha123')
                db.session.commit()
                print("Senha do admin resetada com sucesso")
            else:
                print("Usuário admin não encontrado")
        except Exception as e:
            print(f"Erro ao resetar senha: {str(e)}")

if __name__ == '__main__':
    reset_admin() 