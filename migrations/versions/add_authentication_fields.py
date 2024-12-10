"""Add authentication fields to user table

Revision ID: add_authentication_fields
Revises: merged_migrations
Create Date: 2024-12-10 03:30:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'add_authentication_fields'
down_revision = 'merged_migrations'
branch_labels = None
depends_on = None

def upgrade():
    # Add email and password_hash columns to user table
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('email', sa.String(length=120), nullable=True))
        batch_op.add_column(sa.Column('password_hash', sa.String(length=60), nullable=True))
        batch_op.create_unique_constraint('uq_user_email', ['email'])

def downgrade():
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_constraint('uq_user_email', type_='unique')
        batch_op.drop_column('password_hash')
        batch_op.drop_column('email')
