"""Implement Discord-like profile system

Revision ID: 364f9d08f46b
Revises: 36e162f979b0
Create Date: 2024-12-11 14:55:04.786256

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '364f9d08f46b'
down_revision = '36e162f979b0'
branch_labels = None
depends_on = None


def upgrade():
    # Get database connection and inspector
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    
    # Handle channel table modifications
    existing_channel_columns = [col['name'] for col in inspector.get_columns('channel')]
    existing_constraints = inspector.get_foreign_keys('channel')
    
    # Drop category foreign key if it exists
    for fk in existing_constraints:
        if fk['referred_table'] == 'category':
            op.drop_constraint(fk['name'], 'channel', type_='foreignkey')
    
    # Drop category table if it exists
    try:
        op.drop_table('category')
    except (sa.exc.OperationalError, sa.exc.ProgrammingError):
        pass
    
    # Modify channel table
    with op.batch_alter_table('channel', schema=None) as batch_op:
        # Drop columns if they exist
        if 'category_id' in existing_channel_columns:
            batch_op.drop_column('category_id')
        if 'is_private' in existing_channel_columns:
            batch_op.drop_column('is_private')
            
        # Add type column if it doesn't exist
        if 'type' not in existing_channel_columns:
            batch_op.add_column(sa.Column('type', sa.String(length=20), nullable=True))
        
        # Modify existing columns
        batch_op.alter_column('name',
               existing_type=sa.VARCHAR(length=50),
               type_=sa.String(length=100),
               existing_nullable=False)
        batch_op.alter_column('description',
               existing_type=sa.VARCHAR(length=200),
               type_=sa.String(length=500),
               existing_nullable=True)
        batch_op.alter_column('created_at',
               existing_type=postgresql.TIMESTAMP(),
               nullable=True)

    # Handle user table modifications for Discord-like profile system
    existing_user_columns = [col['name'] for col in inspector.get_columns('user')]
    
    with op.batch_alter_table('user', schema=None) as batch_op:
        # Drop deprecated columns if they exist
        deprecated_columns = ['location', 'contact_info', 'timezone']
        for col in deprecated_columns:
            if col in existing_user_columns:
                batch_op.drop_column(col)
        
        # Add new Discord-like columns if they don't exist
        new_columns = {
            'discriminator': sa.String(length=4),
            'banner': sa.String(length=200),
            'locale': sa.String(length=10),
            'activity_type': sa.String(length=50),
            'activity_name': sa.String(length=100),
            'status_emoji': sa.String(length=50),
            'bio': sa.String(length=500)
        }
        
        for col_name, col_type in new_columns.items():
            if col_name not in existing_user_columns:
                batch_op.add_column(sa.Column(col_name, col_type, nullable=True))
        
        # Modify existing columns
        batch_op.alter_column('password_hash',
               existing_type=sa.VARCHAR(length=60),
               type_=sa.String(length=128),
               existing_nullable=False)
               
        batch_op.alter_column('profile_theme',
               existing_type=sa.VARCHAR(length=50),
               type_=sa.String(length=20),
               existing_nullable=True,
               server_default='dark')
               
        batch_op.alter_column('connections',
               existing_type=postgresql.JSONB(astext_type=sa.Text()),
               type_=sa.JSON(),
               existing_nullable=True,
               server_default='{}')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('timezone', sa.VARCHAR(length=50), autoincrement=False, nullable=True))
        batch_op.add_column(sa.Column('contact_info', postgresql.JSON(astext_type=sa.Text()), autoincrement=False, nullable=True))
        batch_op.add_column(sa.Column('location', sa.VARCHAR(length=100), autoincrement=False, nullable=True))
        batch_op.alter_column('connections',
               existing_type=sa.JSON(),
               type_=postgresql.JSONB(astext_type=sa.Text()),
               existing_nullable=True,
               existing_server_default=sa.text("'{}'::jsonb"))
        batch_op.alter_column('profile_theme',
               existing_type=sa.String(length=20),
               type_=sa.VARCHAR(length=50),
               existing_nullable=True,
               existing_server_default=sa.text("'dark'::character varying"))
        batch_op.alter_column('password_hash',
               existing_type=sa.String(length=128),
               type_=sa.VARCHAR(length=60),
               existing_nullable=False)
        batch_op.drop_column('locale')
        batch_op.drop_column('discriminator')

    with op.batch_alter_table('channel', schema=None) as batch_op:
        batch_op.add_column(sa.Column('category_id', sa.INTEGER(), autoincrement=False, nullable=False))
        batch_op.add_column(sa.Column('is_private', sa.BOOLEAN(), autoincrement=False, nullable=True))
        batch_op.create_foreign_key('channel_category_id_fkey', 'category', ['category_id'], ['id'])
        batch_op.alter_column('created_at',
               existing_type=postgresql.TIMESTAMP(),
               nullable=False)
        batch_op.alter_column('description',
               existing_type=sa.String(length=500),
               type_=sa.VARCHAR(length=200),
               existing_nullable=True)
        batch_op.alter_column('name',
               existing_type=sa.String(length=100),
               type_=sa.VARCHAR(length=50),
               existing_nullable=False)
        batch_op.drop_column('type')

    op.create_table('category',
        sa.Column('id', sa.INTEGER(), autoincrement=True, nullable=False),
        sa.Column('name', sa.VARCHAR(length=50), autoincrement=False, nullable=False),
        sa.Column('description', sa.VARCHAR(length=200), autoincrement=False, nullable=True),
        sa.Column('created_at', postgresql.TIMESTAMP(), autoincrement=False, nullable=False),
        sa.PrimaryKeyConstraint('id', name='category_pkey'),
        sa.UniqueConstraint('name', name='category_name_key')
    )
    # ### end Alembic commands ###