"""remove unused columns

Revision ID: 20241211_remove_unused_columns
Revises: 669f0ddab0f4
Create Date: 2024-12-11 17:08:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '20241211_remove_unused_columns'
down_revision = '669f0ddab0f4'
branch_labels = None
depends_on = None

def upgrade():
    # Remove unused columns
    with op.batch_alter_table('user') as batch_op:
        batch_op.drop_column('banner')
        batch_op.drop_column('accent_color')
        batch_op.drop_column('last_seen')

def downgrade():
    # Add back removed columns
    with op.batch_alter_table('user') as batch_op:
        batch_op.add_column(sa.Column('banner', sa.String(200), nullable=True))
        batch_op.add_column(sa.Column('accent_color', sa.String(7), nullable=True))
        batch_op.add_column(sa.Column('last_seen', sa.DateTime, nullable=True))
