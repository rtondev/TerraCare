from http.server import BaseHTTPRequestHandler
from app import app, db, User, hash_password

def sync_database():
    with app.app_context():
        try:
            # Criar tabelas
            db.create_all()
            
            # Verificar/criar usuário admin
            admin = User.query.filter_by(email='admin@admin.admin').first()
            if not admin:
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
                return "Admin user created successfully"
            return "Admin user already exists"
        except Exception as e:
            return str(e)

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            result = sync_database()
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(result.encode())
        except Exception as e:
            self.send_response(500)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(str(e).encode()) 