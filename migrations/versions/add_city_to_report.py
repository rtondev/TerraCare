"""add city column to report

Revision ID: 1a2b3c4d5e6f
Revises: 
Create Date: 2024-01-01 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '1a2b3c4d5e6f'
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    # Adicionar coluna city se ela não existir
    op.execute("""
        SELECT COUNT(*)
        FROM information_schema.columns 
        WHERE table_name = 'report'
        AND column_name = 'city'
        AND table_schema = DATABASE()
    """)
    
    result = op.get_bind().execute().scalar()
    
    if result == 0:
        # Coluna não existe, então vamos criá-la
        op.add_column('report', sa.Column('city', sa.String(100), nullable=True))
        
        # Atualizar registros existentes com a cidade do usuário
        op.execute('''
            UPDATE report r
            INNER JOIN user u ON r.user_id = u.id
            SET r.city = u.city
            WHERE r.city IS NULL
        ''')

def downgrade():
    op.drop_column('report', 'city') 