"""Add presence_state column

Revision ID: add_presence_state
Revises: 
Create Date: 2024-12-11 19:45:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'add_presence_state'
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    # Add presence_state column with default value 'online'
    op.add_column('user', sa.Column('presence_state', sa.String(20), nullable=False, server_default='online'))

def downgrade():
    op.drop_column('user', 'presence_state')
