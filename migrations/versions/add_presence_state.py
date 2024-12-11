"""add presence state column

Revision ID: add_presence_state_20241211
Revises: merged_migrations
Create Date: 2024-12-11

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic
revision = 'add_presence_state_20241211'
down_revision = 'merged_migrations'
branch_labels = None
depends_on = None

def upgrade():
    # Add presence_state column with default value 'online'
    op.add_column('user', 
        sa.Column('presence_state', sa.String(20), nullable=True, server_default='online')
    )

def downgrade():
    # Remove presence_state column
    op.drop_column('user', 'presence_state')
