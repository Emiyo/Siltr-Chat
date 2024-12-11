"""Merged profile system migrations

Revision ID: merged_profile_system
Revises: merged_migrations
Create Date: 2024-12-11 18:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'merged_profile_system'
down_revision = 'merged_migrations'
branch_labels = None
depends_on = None

def upgrade():
    # Add new profile system columns
    op.add_column('user', sa.Column('banner', sa.String(length=200), nullable=True))
    op.add_column('user', sa.Column('status_emoji', sa.String(length=20), nullable=True))
    op.add_column('user', sa.Column('presence_details', postgresql.JSON(astext_type=sa.Text()), nullable=True))
    op.add_column('user', sa.Column('accent_color', sa.String(length=7), nullable=True, server_default='#5865F2'))
    
    # Update preferences with default values
    default_preferences = {
        'notifications': True,
        'message_display': 'cozy',
        'emoji_style': 'native',
        'language': 'en'
    }
    
    op.execute(f"""
        UPDATE "user" 
        SET preferences = '{default_preferences}'::jsonb 
        WHERE preferences IS NULL
    """)

def downgrade():
    op.drop_column('user', 'banner')
    op.drop_column('user', 'status_emoji')
    op.drop_column('user', 'presence_details')
    op.drop_column('user', 'accent_color')
