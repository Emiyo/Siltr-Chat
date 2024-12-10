"""Add roles and permissions tables

Revision ID: add_roles_and_permissions
Revises: add_authentication_fields
Create Date: 2024-12-10 03:45:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'add_roles_and_permissions'
down_revision = 'add_authentication_fields'
branch_labels = None
depends_on = None

def upgrade():
    # Create roles table
    op.create_table('role',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=50), nullable=False),
        sa.Column('description', sa.String(length=200)),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name')
    )

    # Create permissions table
    op.create_table('permission',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=50), nullable=False),
        sa.Column('description', sa.String(length=200)),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name')
    )

    # Create role_permissions association table
    op.create_table('role_permissions',
        sa.Column('role_id', sa.Integer(), nullable=False),
        sa.Column('permission_id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['role_id'], ['role.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['permission_id'], ['permission.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('role_id', 'permission_id')
    )

    # Create user_roles association table
    op.create_table('user_roles',
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('role_id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['user.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['role_id'], ['role.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('user_id', 'role_id')
    )

    # Insert default roles
    op.execute(
        """
        INSERT INTO role (name, description) VALUES
        ('admin', 'Administrator with full access'),
        ('moderator', 'User with moderation privileges'),
        ('user', 'Regular user')
        """
    )

    # Insert default permissions
    op.execute(
        """
        INSERT INTO permission (name, description) VALUES
        ('manage_users', 'Can manage user accounts'),
        ('manage_roles', 'Can manage user roles'),
        ('manage_channels', 'Can manage chat channels'),
        ('moderate_messages', 'Can moderate chat messages'),
        ('create_channels', 'Can create new channels'),
        ('mute_users', 'Can mute users'),
        ('send_messages', 'Can send messages')
        """
    )

    # Assign permissions to roles
    op.execute(
        """
        -- Admin role permissions
        INSERT INTO role_permissions (role_id, permission_id)
        SELECT r.id, p.id
        FROM role r, permission p
        WHERE r.name = 'admin';

        -- Moderator role permissions
        INSERT INTO role_permissions (role_id, permission_id)
        SELECT r.id, p.id
        FROM role r, permission p
        WHERE r.name = 'moderator' 
        AND p.name IN ('moderate_messages', 'mute_users', 'manage_channels', 'send_messages');

        -- User role permissions
        INSERT INTO role_permissions (role_id, permission_id)
        SELECT r.id, p.id
        FROM role r, permission p
        WHERE r.name = 'user' 
        AND p.name IN ('send_messages');
        """
    )

def downgrade():
    op.drop_table('user_roles')
    op.drop_table('role_permissions')
    op.drop_table('permission')
    op.drop_table('role')
