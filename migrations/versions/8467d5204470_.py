"""empty message

Revision ID: 8467d5204470
Revises: 4fcbdf5c64d6, add_extended_profile_fields, add_muted_until, add_password_reset_token, add_verification_fields
Create Date: 2024-12-11 03:21:25.447383

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '8467d5204470'
down_revision = ('4fcbdf5c64d6', 'add_extended_profile_fields', 'add_muted_until', 'add_password_reset_token', 'add_verification_fields')
branch_labels = None
depends_on = None


def upgrade():
    pass


def downgrade():
    pass
