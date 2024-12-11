"""Simplify profile system

Revision ID: simplify_profile_system
Revises: 364f9d08f46b
Create Date: 2024-12-11 15:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'simplify_profile_system'
down_revision = '364f9d08f46b'
branch_labels = None
depends_on = None

def upgrade():
    # Get database connection
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    
    # Get existing columns
    existing_columns = [col['name'] for col in inspector.get_columns('user')]
    
    with op.batch_alter_table('user', schema=None) as batch_op:
        # Keep essential columns, drop the rest
        columns_to_drop = [
            'status_emoji',
            'status_expires_at',
            'presence_updated_at',
            'activity_type',
            'activity_name',
            'activity_details',
            'activity_state',
            'activity_party',
            'activity_assets',
            'activity_started_at',
            'activity_buttons',
            'pronouns',
            'badges',
            'custom_badges',
            'premium_since',
            'locale',
            'connections',
            'discriminator',
            'banner',
            'banner_color'
        ]
        
        # Only drop columns that exist
        for column in columns_to_drop:
            if column in existing_columns:
                batch_op.drop_column(column)
        
        # Add or modify essential columns
        if 'bio' not in existing_columns:
            batch_op.add_column(sa.Column('bio', sa.String(length=500), nullable=True))
        
        # Ensure core columns have correct types
        batch_op.alter_column('status',
            existing_type=sa.String(length=100),
            nullable=True)
        batch_op.alter_column('presence_state',
            existing_type=sa.String(length=20),
            nullable=True,
            server_default='online')
        batch_op.alter_column('profile_theme',
            existing_type=sa.String(length=20),
            nullable=True,
            server_default='dark')

def downgrade():
    # Note: This is a destructive change, so downgrade just keeps the simplified schema
    pass
