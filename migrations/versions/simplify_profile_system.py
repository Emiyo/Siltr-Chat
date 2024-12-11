"""Simplify profile system

Revision ID: simplify_profile_system
Revises: merged_migrations
Create Date: 2024-12-11 15:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'simplify_profile_system'
down_revision = 'merged_migrations'
branch_labels = None
depends_on = None

def upgrade():
    # Create temporary table with simplified schema
    op.create_table('user_new',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('username', sa.String(length=50), nullable=False),
        sa.Column('email', sa.String(length=120), nullable=False),
        sa.Column('password_hash', sa.String(length=128), nullable=False),
        sa.Column('display_name', sa.String(length=50), nullable=True),
        sa.Column('avatar', sa.String(length=200), nullable=True),
        sa.Column('bio', sa.String(length=500), nullable=True),
        sa.Column('status', sa.String(length=100), nullable=True),
        sa.Column('presence_state', sa.String(length=20), nullable=False, server_default='offline'),
        sa.Column('theme', sa.String(length=20), nullable=False, server_default='dark'),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('NOW()')),
        sa.Column('last_seen', sa.DateTime(), nullable=True),
        sa.Column('is_verified', sa.Boolean(), nullable=False, server_default='false'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('username'),
        sa.UniqueConstraint('email')
    )
    
    # Copy data from old table to new table
    op.execute("""
        INSERT INTO user_new (
            id, username, email, password_hash, display_name, avatar, bio,
            status, presence_state, created_at, last_seen, is_verified
        )
        SELECT 
            id, username, email, password_hash, display_name, avatar, bio,
            status, COALESCE(presence_state, 'offline'), created_at, last_seen, is_verified
        FROM "user"
    """)
    
    # Drop old table and rename new table
    op.drop_table('user')
    op.rename_table('user_new', 'user')

def downgrade():
    # We cannot restore the dropped columns, so downgrade is not supported
    pass
