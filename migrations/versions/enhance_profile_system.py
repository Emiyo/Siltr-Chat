"""Enhance profile system with Discord-like features

Revision ID: enhance_profile_system
Revises: de20893e2368
Create Date: 2024-12-11 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

# revision identifiers, used by Alembic.
revision = 'enhance_profile_system'
down_revision = 'de20893e2368'
branch_labels = None
depends_on = None

def upgrade():
    # Add new profile customization fields
    with op.batch_alter_table('user', schema=None) as batch_op:
        # Activity and presence
        batch_op.add_column(sa.Column('activity_status', sa.String(50), nullable=True))
        batch_op.add_column(sa.Column('activity_type', sa.String(20), nullable=True))
        batch_op.add_column(sa.Column('activity_details', JSONB, nullable=True))
        
        # Profile customization
        batch_op.add_column(sa.Column('profile_badges', JSONB, nullable=True))
        batch_op.add_column(sa.Column('custom_status_expires_at', sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column('banner_color', sa.String(7), nullable=True))
        
        # Social connections
        batch_op.add_column(sa.Column('connections', JSONB, nullable=True))
        
        # Privacy settings
        batch_op.add_column(sa.Column('privacy_settings', JSONB, nullable=True,
            server_default=sa.text("'{\"show_current_activity\": true, \"show_status\": true}'::jsonb")))

def downgrade():
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('activity_status')
        batch_op.drop_column('activity_type')
        batch_op.drop_column('activity_details')
        batch_op.drop_column('profile_badges')
        batch_op.drop_column('custom_status_expires_at')
        batch_op.drop_column('banner_color')
        batch_op.drop_column('connections')
        batch_op.drop_column('privacy_settings')
