"""Add message replies, forwarding and user profiles

Revision ID: add_messaging_and_profiles
Revises: add_categories_and_channels
Create Date: 2024-12-11 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'add_messaging_and_profiles'
down_revision = 'add_categories_and_channels'
branch_labels = None
depends_on = None

def upgrade():
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    
    # Add message threading and forwarding columns
    with op.batch_alter_table('message', schema=None) as batch_op:
        # Check existing columns and constraints
        existing_columns = [c['name'] for c in inspector.get_columns('message')]
        existing_fks = [fk['name'] for fk in inspector.get_foreign_keys('message')]
        
        # Add new columns if they don't exist
        if 'reply_to_id' not in existing_columns:
            batch_op.add_column(sa.Column('reply_to_id', sa.Integer(), nullable=True))
        if 'forwarded_from_id' not in existing_columns:
            batch_op.add_column(sa.Column('forwarded_from_id', sa.Integer(), nullable=True))
        if 'thread_id' not in existing_columns:
            batch_op.add_column(sa.Column('thread_id', sa.Integer(), nullable=True))
        if 'is_edited' not in existing_columns:
            batch_op.add_column(sa.Column('is_edited', sa.Boolean(), nullable=False, server_default='false'))
        
        # Add foreign key constraints if they don't exist
        if 'fk_message_reply_to' not in existing_fks:
            batch_op.create_foreign_key('fk_message_reply_to', 'message', ['reply_to_id'], ['id'])
        if 'fk_message_forwarded_from' not in existing_fks:
            batch_op.create_foreign_key('fk_message_forwarded_from', 'message', ['forwarded_from_id'], ['id'])
        if 'fk_message_thread' not in existing_fks:
            batch_op.create_foreign_key('fk_message_thread', 'message', ['thread_id'], ['id'])

    # Enhance user profiles
    with op.batch_alter_table('user', schema=None) as batch_op:
        # Check existing columns
        existing_columns = [c['name'] for c in inspector.get_columns('user')]
        
        # Add new columns if they don't exist
        if 'bio' not in existing_columns:
            batch_op.add_column(sa.Column('bio', sa.String(length=500), nullable=True))
        if 'display_name' not in existing_columns:
            batch_op.add_column(sa.Column('display_name', sa.String(length=50), nullable=True))
        if 'last_seen' not in existing_columns:
            batch_op.add_column(sa.Column('last_seen', sa.DateTime(), nullable=True))
        if 'warning_count' not in existing_columns:
            batch_op.add_column(sa.Column('warning_count', sa.Integer(), nullable=False, server_default='0'))

def downgrade():
    # Remove message threading and forwarding columns
    with op.batch_alter_table('message', schema=None) as batch_op:
        batch_op.drop_constraint('fk_message_thread', type_='foreignkey')
        batch_op.drop_constraint('fk_message_forwarded_from', type_='foreignkey')
        batch_op.drop_constraint('fk_message_reply_to', type_='foreignkey')
        batch_op.drop_column('is_edited')
        batch_op.drop_column('thread_id')
        batch_op.drop_column('forwarded_from_id')
        batch_op.drop_column('reply_to_id')

    # Remove enhanced user profile columns
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('warning_count')
        batch_op.drop_column('last_seen')
        batch_op.drop_column('display_name')
        batch_op.drop_column('bio')
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'add_messaging_and_profiles'
down_revision = 'add_categories_and_channels'
branch_labels = None
depends_on = None

def upgrade():
    # Add message threading and forwarding columns
    with op.batch_alter_table('message', schema=None) as batch_op:
        batch_op.add_column(sa.Column('reply_to_id', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('forwarded_from_id', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('thread_id', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('is_edited', sa.Boolean(), nullable=False, server_default='false'))
        batch_op.create_foreign_key('fk_message_reply_to', 'message', ['reply_to_id'], ['id'])
        batch_op.create_foreign_key('fk_message_forwarded_from', 'message', ['forwarded_from_id'], ['id'])
        batch_op.create_foreign_key('fk_message_thread', 'message', ['thread_id'], ['id'])

    # Enhance user profiles
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('bio', sa.String(length=500), nullable=True))
        batch_op.add_column(sa.Column('display_name', sa.String(length=50), nullable=True))
        batch_op.add_column(sa.Column('last_seen', sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column('warning_count', sa.Integer(), nullable=False, server_default='0'))

def downgrade():
    # Remove message threading and forwarding columns
    with op.batch_alter_table('message', schema=None) as batch_op:
        batch_op.drop_constraint('fk_message_thread', type_='foreignkey')
        batch_op.drop_constraint('fk_message_forwarded_from', type_='foreignkey')
        batch_op.drop_constraint('fk_message_reply_to', type_='foreignkey')
        batch_op.drop_column('is_edited')
        batch_op.drop_column('thread_id')
        batch_op.drop_column('forwarded_from_id')
        batch_op.drop_column('reply_to_id')

    # Remove enhanced user profile columns
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('warning_count')
        batch_op.drop_column('last_seen')
        batch_op.drop_column('display_name')
        batch_op.drop_column('bio')
