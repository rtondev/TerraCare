"""Add city and location fields

Revision ID: 76358b2dcdf0
Revises: dadae2d6046c
Create Date: 2025-02-13 08:21:40.428363

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '76358b2dcdf0'
down_revision = 'dadae2d6046c'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('city', sa.String(length=100), nullable=True))
        batch_op.add_column(sa.Column('latitude', sa.Float(), nullable=True))
        batch_op.add_column(sa.Column('longitude', sa.Float(), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('longitude')
        batch_op.drop_column('latitude')
        batch_op.drop_column('city')

    # ### end Alembic commands ###
