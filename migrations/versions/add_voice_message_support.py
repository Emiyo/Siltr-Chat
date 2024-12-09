"""Add voice message support

Revision ID: add_voice_message_support
Revises: merged_migrations
Create Date: 2024-12-09 20:50:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'add_voice_message_support'
down_revision = 'merged_migrations'
branch_labels = None
depends_on = None

def upgrade():
    with op.batch_alter_table('message', schema=None) as batch_op:
        batch_op.add_column(sa.Column('voice_url', sa.String(length=200), nullable=True))
        batch_op.add_column(sa.Column('voice_duration', sa.Float, nullable=True))

def downgrade():
    with op.batch_alter_table('message', schema=None) as batch_op:
        batch_op.drop_column('voice_duration')
        batch_op.drop_column('voice_url')
