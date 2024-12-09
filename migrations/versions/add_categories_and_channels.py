"""Add categories and channels

Revision ID: add_categories_and_channels
Revises: add_voice_message_support
Create Date: 2024-12-09 22:07:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'add_categories_and_channels'
down_revision = 'add_voice_message_support'
branch_labels = None
depends_on = None

def upgrade():
    # Create category table
    op.create_table('category',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=50), nullable=False),
        sa.Column('description', sa.String(length=200)),
        sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.text('NOW()')),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name')
    )

    # Create channel table
    op.create_table('channel',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('category_id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=50), nullable=False),
        sa.Column('description', sa.String(length=200)),
        sa.Column('is_private', sa.Boolean(), default=False),
        sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.text('NOW()')),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['category_id'], ['category.id'], name='fk_channel_category'),
        sa.UniqueConstraint('category_id', 'name', name='uq_channel_category_name')
    )

    # Add channel_id to message table
    with op.batch_alter_table('message', schema=None) as batch_op:
        batch_op.add_column(sa.Column('channel_id', sa.Integer(), nullable=True))
        batch_op.create_foreign_key('fk_message_channel', 'channel', ['channel_id'], ['id'])

def downgrade():
    with op.batch_alter_table('message', schema=None) as batch_op:
        batch_op.drop_constraint('fk_message_channel', type_='foreignkey')
        batch_op.drop_column('channel_id')
    
    op.drop_table('channel')
    op.drop_table('category')
