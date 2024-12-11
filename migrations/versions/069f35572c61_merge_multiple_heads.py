"""merge multiple heads

Revision ID: 069f35572c61
Revises: 20241211_remove_unused_columns, remove_unused_columns
Create Date: 2024-12-11 17:53:24.524717

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '069f35572c61'
down_revision = ('20241211_remove_unused_columns', 'remove_unused_columns')
branch_labels = None
depends_on = None


def upgrade():
    pass


def downgrade():
    pass
