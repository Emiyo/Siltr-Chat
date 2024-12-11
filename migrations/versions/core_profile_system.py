"""Core profile system implementation

Revision ID: core_profile_system
Revises: merged_migrations
Create Date: 2024-12-11 16:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'core_profile_system'
down_revision = 'merged_migrations'
branch_labels = None
depends_on = None

def upgrade():
    # Create new tables with core functionality
    op.create_table('new_user',
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
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('is_verified', sa.Boolean(), nullable=False, server_default='false'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('username'),
        sa.UniqueConstraint('email')
    )

    # Create new message table with proper foreign keys
    op.create_table('new_message',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('type', sa.String(length=20), nullable=False),
        sa.Column('sender_id', sa.Integer(), nullable=True),
        sa.Column('receiver_id', sa.Integer(), nullable=True),
        sa.Column('text', sa.Text(), nullable=False),
        sa.Column('timestamp', sa.DateTime(), nullable=False, server_default=sa.text('NOW()')),
        sa.Column('file_url', sa.String(length=200), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )

    # Copy data from old tables to new ones
    op.execute("""
        INSERT INTO new_user (
            id, username, email, password_hash, display_name, avatar, bio,
            status, presence_state, created_at, last_seen, is_verified
        )
        SELECT 
            id, username, email, password_hash, display_name, avatar, bio,
            status, COALESCE(presence_state, 'offline'), created_at, last_seen, is_verified
        FROM "user"
    """)

    op.execute("""
        INSERT INTO new_message (
            id, type, sender_id, receiver_id, text, timestamp, file_url
        )
        SELECT 
            id, type, sender_id, receiver_id, text, timestamp, file_url
        FROM message
    """)

    # Drop old tables and constraints
    op.execute('DROP TABLE IF EXISTS "user" CASCADE')
    op.execute('DROP TABLE IF EXISTS message CASCADE')
    
    # Rename new tables to final names
    op.rename_table('new_user', 'user')
    op.rename_table('new_message', 'message')

    # Add foreign key constraints
    op.create_foreign_key('fk_message_sender', 'message', 'user',
                         ['sender_id'], ['id'], ondelete='SET NULL')
    op.create_foreign_key('fk_message_receiver', 'message', 'user',
                         ['receiver_id'], ['id'], ondelete='SET NULL')

def downgrade():
    op.drop_table('message')
    op.drop_table('user')
