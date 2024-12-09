"""Add message threading support

Revision ID: add_message_threading
Revises: add_categories_and_channels
Create Date: 2024-12-09 22:30:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'add_message_threading'
down_revision = 'add_categories_and_channels'
branch_labels = None
depends_on = None

def upgrade():
    with op.batch_alter_table('message', schema=None) as batch_op:
        batch_op.add_column(sa.Column('parent_id', sa.Integer(), nullable=True))
        batch_op.create_foreign_key('fk_message_parent', 'message', ['parent_id'], ['id'])
        batch_op.add_column(sa.Column('thread_count', sa.Integer(), nullable=False, server_default='0'))

def downgrade():
    with op.batch_alter_table('message', schema=None) as batch_op:
        batch_op.drop_constraint('fk_message_parent', type_='foreignkey')
        batch_op.drop_column('thread_count')
        batch_op.drop_column('parent_id')
