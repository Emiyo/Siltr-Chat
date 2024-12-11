"""Fix user profile schema

Revision ID: fix_user_profile_schema
Revises: core_profile_system
Create Date: 2024-12-11 16:30:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'fix_user_profile_schema'
down_revision = 'core_profile_system'
branch_labels = None
depends_on = None

def upgrade():
    # Add missing columns that don't exist yet
    with op.batch_alter_table('user', schema=None) as batch_op:
        # Add warning_count if it doesn't exist
        batch_op.add_column(sa.Column('warning_count', sa.Integer, nullable=True, server_default='0'))
        # Add accent_color if it doesn't exist
        batch_op.add_column(sa.Column('accent_color', sa.String(7), nullable=True, server_default='#5865F2'))
        # Add preferences if it doesn't exist
        batch_op.add_column(sa.Column('preferences', sa.JSON(), nullable=True))

def downgrade():
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('preferences')
        batch_op.drop_column('accent_color')
        batch_op.drop_column('warning_count')
