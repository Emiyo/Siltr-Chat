"""Fix message table structure

Revision ID: fix_message_table_structure
Revises: add_password_reset_token
Create Date: 2024-12-11 00:35:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'fix_message_table_structure'
down_revision = 'add_password_reset_token'
branch_labels = None
depends_on = None

def upgrade():
    # Create message table with proper structure
    op.create_table('message',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('sender_id', sa.Integer(), nullable=True),
        sa.Column('receiver_id', sa.Integer(), nullable=True),
        sa.Column('channel_id', sa.Integer(), nullable=True),
        sa.Column('text', sa.Text(), nullable=False),
        sa.Column('timestamp', sa.DateTime(), nullable=False, server_default=sa.text('NOW()')),
        sa.Column('type', sa.String(length=20), nullable=False, server_default='public'),
        sa.Column('file_url', sa.String(length=200), nullable=True),
        sa.Column('voice_url', sa.String(length=200), nullable=True),
        sa.Column('voice_duration', sa.Float(), nullable=True),
        sa.Column('encrypted', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('encryption_key_id', sa.String(length=100), nullable=True),
        sa.ForeignKeyConstraint(['sender_id'], ['user.id'], name='fk_message_sender'),
        sa.ForeignKeyConstraint(['receiver_id'], ['user.id'], name='fk_message_receiver'),
        sa.ForeignKeyConstraint(['channel_id'], ['channel.id'], name='fk_message_channel'),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create index for faster message retrieval
    op.create_index('ix_message_timestamp', 'message', ['timestamp'])
    op.create_index('ix_message_sender_id', 'message', ['sender_id'])
    op.create_index('ix_message_channel_id', 'message', ['channel_id'])

def downgrade():
    op.drop_index('ix_message_channel_id')
    op.drop_index('ix_message_sender_id')
    op.drop_index('ix_message_timestamp')
    op.drop_table('message')
