"""Add password reset token field

Revision ID: add_password_reset_token
Revises: add_roles_and_permissions
Create Date: 2024-12-10 03:50:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'add_password_reset_token'
down_revision = 'add_roles_and_permissions'
branch_labels = None
depends_on = None

def upgrade():
    op.add_column('user',
        sa.Column('reset_password_token', sa.String(length=100), nullable=True)
    )
    op.add_column('user',
        sa.Column('reset_password_expires', sa.DateTime(), nullable=True)
    )

def downgrade():
    op.drop_column('user', 'reset_password_expires')
    op.drop_column('user', 'reset_password_token')
