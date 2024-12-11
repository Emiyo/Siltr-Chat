"""empty message

Revision ID: 70c94da19415
Revises: add_discord_profile_fields, b9c20718bb9e, fix_user_profile_schema, merged_profile_system, simplify_profile_system
Create Date: 2024-12-11 15:30:20.805042

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '70c94da19415'
down_revision = ('add_discord_profile_fields', 'b9c20718bb9e', 'fix_user_profile_schema', 'merged_profile_system', 'simplify_profile_system')
branch_labels = None
depends_on = None


def upgrade():
    pass


def downgrade():
    pass
