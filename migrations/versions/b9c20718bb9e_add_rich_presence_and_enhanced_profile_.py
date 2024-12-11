"""Add rich presence and enhanced profile fields

Revision ID: b9c20718bb9e
Revises: 364f9d08f46b
Create Date: 2024-12-11 15:01:39.526144

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b9c20718bb9e'
down_revision = '364f9d08f46b'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('banner_color', sa.String(length=7), nullable=True))
        batch_op.add_column(sa.Column('status_expires_at', sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column('presence_updated_at', sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column('activity_details', sa.String(length=100), nullable=True))
        batch_op.add_column(sa.Column('activity_state', sa.String(length=100), nullable=True))
        batch_op.add_column(sa.Column('activity_party', sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column('activity_assets', sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column('activity_started_at', sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column('activity_buttons', sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column('pronouns', sa.String(length=50), nullable=True))
        batch_op.add_column(sa.Column('badges', sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column('custom_badges', sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column('premium_since', sa.DateTime(), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('premium_since')
        batch_op.drop_column('custom_badges')
        batch_op.drop_column('badges')
        batch_op.drop_column('pronouns')
        batch_op.drop_column('activity_buttons')
        batch_op.drop_column('activity_started_at')
        batch_op.drop_column('activity_assets')
        batch_op.drop_column('activity_party')
        batch_op.drop_column('activity_state')
        batch_op.drop_column('activity_details')
        batch_op.drop_column('presence_updated_at')
        batch_op.drop_column('status_expires_at')
        batch_op.drop_column('banner_color')

    # ### end Alembic commands ###
