"""add muted until column

Revision ID: add_muted_until
Revises: 
Create Date: 2024-12-09 15:47:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'add_muted_until'
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    op.add_column('user', sa.Column('muted_until', sa.DateTime, nullable=True))

def downgrade():
    op.drop_column('user', 'muted_until')
