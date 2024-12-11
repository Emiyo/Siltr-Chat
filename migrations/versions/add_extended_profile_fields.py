"""Add extended profile fields

Revision ID: add_extended_profile_fields
Revises: add_messaging_and_profiles
Create Date: 2024-12-11 11:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'add_extended_profile_fields'
down_revision = 'add_messaging_and_profiles'
branch_labels = None
depends_on = None

def upgrade():
    # Get database connection and inspector
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    
    # Get existing columns
    existing_columns = [c['name'] for c in inspector.get_columns('user')]
    
    # Add new columns if they don't exist
    with op.batch_alter_table('user', schema=None) as batch_op:
        if 'location' not in existing_columns:
            batch_op.add_column(sa.Column('location', sa.String(length=100), nullable=True))
        if 'timezone' not in existing_columns:
            batch_op.add_column(sa.Column('timezone', sa.String(length=50), nullable=True))
        if 'preferences' not in existing_columns:
            batch_op.add_column(sa.Column('preferences', sa.JSON(), nullable=True))
        if 'contact_info' not in existing_columns:
            batch_op.add_column(sa.Column('contact_info', sa.JSON(), nullable=True))

def downgrade():
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('contact_info')
        batch_op.drop_column('preferences')
        batch_op.drop_column('timezone')
        batch_op.drop_column('location')
