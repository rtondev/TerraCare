from app import app, db, User, Report
from flask_migrate import Migrate, upgrade
from sqlalchemy import text

def migrate_db():
    with app.app_context():
        try:
            # Verificar se a coluna city existe na tabela report
            result = db.session.execute(text("""
                SELECT COUNT(*)
                FROM information_schema.columns 
                WHERE table_name = 'report'
                AND column_name = 'city'
                AND table_schema = DATABASE()
            """))
            
            column_exists = result.scalar() > 0
            
            if not column_exists:
                print("Adicionando coluna city à tabela report...")
                db.session.execute(text("""
                    ALTER TABLE report
                    ADD COLUMN city VARCHAR(100)
                """))
                
                # Atualizar cidade das denúncias existentes
                print("Atualizando cidades das denúncias existentes...")
                db.session.execute(text("""
                    UPDATE report r
                    INNER JOIN user u ON r.user_id = u.id
                    SET r.city = u.city
                    WHERE r.city IS NULL
                """))
                
                db.session.commit()
                print("Coluna city adicionada e atualizada com sucesso!")
            else:
                print("Coluna city já existe na tabela report")

            # Verificar denúncias sem cidade
            reports_without_city = Report.query.filter_by(city=None).all()
            if reports_without_city:
                print(f"Atualizando {len(reports_without_city)} denúncias sem cidade...")
                for report in reports_without_city:
                    user = User.query.get(report.user_id)
                    if user and user.city:
                        report.city = user.city
                db.session.commit()
                print("Denúncias atualizadas com sucesso!")

            print("Migração concluída com sucesso!")
            
        except Exception as e:
            print(f"Erro durante a migração: {str(e)}")
            db.session.rollback()
            raise e

if __name__ == '__main__':
    migrate_db() 