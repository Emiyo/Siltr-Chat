"""Add verification fields

Revision ID: add_verification_fields
Revises: add_messaging_and_profiles
Create Date: 2024-12-11 11:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'add_verification_fields'
down_revision = 'add_messaging_and_profiles'
branch_labels = None
depends_on = None

def upgrade():
    # Add verification fields to user table
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('is_verified', sa.Boolean(), nullable=False, server_default='false'))
        batch_op.add_column(sa.Column('verification_token', sa.String(length=100), nullable=True))
        batch_op.add_column(sa.Column('verification_sent_at', sa.DateTime(), nullable=True))

def downgrade():
    # Remove verification fields
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('verification_sent_at')
        batch_op.drop_column('verification_token')
        batch_op.drop_column('is_verified')
