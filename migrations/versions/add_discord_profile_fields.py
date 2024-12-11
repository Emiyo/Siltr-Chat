"""Add Discord-like profile fields

Revision ID: add_discord_profile_fields
Create Date: 2024-12-11 17:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'add_discord_profile_fields'
down_revision = 'core_profile_system'
branch_labels = None
depends_on = None

def upgrade():
    # Add new columns for Discord-like profile features
    op.add_column('user', sa.Column('banner', sa.String(length=200), nullable=True))
    op.add_column('user', sa.Column('status_emoji', sa.String(length=20), nullable=True))
    op.add_column('user', sa.Column('presence_details', postgresql.JSON(astext_type=sa.Text()), nullable=True))
    
    # Set default preferences for existing users
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
