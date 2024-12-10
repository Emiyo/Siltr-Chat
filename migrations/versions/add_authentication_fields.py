"""Add authentication fields to user table

Revision ID: add_authentication_fields
Revises: merged_migrations
Create Date: 2024-12-10 03:30:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'add_authentication_fields'
down_revision = 'add_categories_and_channels'
branch_labels = None
depends_on = None

def upgrade():
    # Create user table if it doesn't exist
    op.create_table('user',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('username', sa.String(length=50), nullable=False),
        sa.Column('email', sa.String(length=120), nullable=False),
        sa.Column('password_hash', sa.String(length=60), nullable=False),
        sa.Column('is_moderator', sa.Boolean(), default=False),
        sa.Column('avatar', sa.String(length=200)),
        sa.Column('status', sa.String(length=100)),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('NOW()')),
        sa.Column('muted_until', sa.DateTime()),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('username'),
        sa.UniqueConstraint('email', name='uq_user_email')
    )

def downgrade():
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_constraint('uq_user_email', type_='unique')
        batch_op.drop_column('password_hash')
        batch_op.drop_column('email')
