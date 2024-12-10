"""Merged initial migrations

Revision ID: merged_migrations
Revises: 
Create Date: 2024-12-09 20:45:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'merged_migrations'
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    # Add columns to user table if it exists, create if it doesn't
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    tables = inspector.get_table_names()
    
    if 'user' not in tables:
        op.create_table('user',
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('username', sa.String(length=50), nullable=False),
            sa.Column('is_moderator', sa.Boolean(), default=False),
            sa.Column('avatar', sa.String(length=200)),
            sa.Column('status', sa.String(length=100)),
            sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.text('NOW()')),
            sa.Column('muted_until', sa.DateTime, nullable=True),
            sa.PrimaryKeyConstraint('id'),
            sa.UniqueConstraint('username')
        )
    else:
        # Add columns if they don't exist
        columns = [c['name'] for c in inspector.get_columns('user')]
        if 'muted_until' not in columns:
            op.add_column('user', sa.Column('muted_until', sa.DateTime, nullable=True))
        if 'is_moderator' not in columns:
            op.add_column('user', sa.Column('is_moderator', sa.Boolean(), server_default='false'))
        if 'avatar' not in columns:
            op.add_column('user', sa.Column('avatar', sa.String(length=200)))
        if 'status' not in columns:
            op.add_column('user', sa.Column('status', sa.String(length=100)))

    # Handle message table
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    tables = inspector.get_table_names()
    
    if 'message' in tables:
        # Alter existing message table
        with op.batch_alter_table('message', schema=None) as batch_op:
            # Add columns if they don't exist
            columns = [c['name'] for c in inspector.get_columns('message')]
            if 'type' not in columns:
                batch_op.add_column(sa.Column('type', sa.String(length=20), nullable=False, server_default='public'))
            if 'sender_id' not in columns:
                batch_op.add_column(sa.Column('sender_id', sa.Integer(), nullable=True))
            if 'receiver_id' not in columns:
                batch_op.add_column(sa.Column('receiver_id', sa.Integer(), nullable=True))
            if 'text' not in columns:
                batch_op.add_column(sa.Column('text', sa.Text(), nullable=False, server_default=''))
            if 'timestamp' not in columns:
                batch_op.add_column(sa.Column('timestamp', sa.DateTime, nullable=False, server_default=sa.text('NOW()')))
            if 'file_url' not in columns:
                batch_op.add_column(sa.Column('file_url', sa.String(length=200)))
            if 'reactions' not in columns:
                batch_op.add_column(sa.Column('reactions', sa.JSON(), server_default='{}'))
            
            # Add foreign key constraints if they don't exist
            batch_op.create_foreign_key('fk_sender', 'user', ['sender_id'], ['id'])
            batch_op.create_foreign_key('fk_receiver', 'user', ['receiver_id'], ['id'])
    else:
        # Create new message table
        op.create_table('message',
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('type', sa.String(length=20), nullable=False),
            sa.Column('sender_id', sa.Integer(), nullable=True),
            sa.Column('receiver_id', sa.Integer(), nullable=True),
            sa.Column('text', sa.Text(), nullable=False),
            sa.Column('timestamp', sa.DateTime, nullable=False, server_default=sa.text('NOW()')),
            sa.Column('file_url', sa.String(length=200)),
            sa.Column('reactions', sa.JSON(), server_default='{}'),
            sa.ForeignKeyConstraint(['sender_id'], ['user.id'], name='fk_sender'),
            sa.ForeignKeyConstraint(['receiver_id'], ['user.id'], name='fk_receiver'),
            sa.PrimaryKeyConstraint('id')
        )

def downgrade():
    op.drop_table('message')
    op.drop_table('user')
