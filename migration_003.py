"""Create authentication tables for Module 003.

Revision ID: 003_auth_initial
Revises: 002_tenant_schema
Create Date: 2024-01-20 14:22:30.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '003_auth_initial'
down_revision = '002_tenant_schema'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create authentication tables."""
    
    # Create Users table
    op.create_table(
        'users',
        sa.Column('id', postgresql.UUID(as_uuid=False), nullable=False),
        sa.Column('first_name', sa.String(100), nullable=False),
        sa.Column('last_name', sa.String(100), nullable=False),
        sa.Column('email', sa.String(255), nullable=False),
        sa.Column('username', sa.String(100), nullable=False),
        sa.Column('phone', sa.String(20), nullable=True),
        sa.Column('password_hash', sa.String(255), nullable=False),
        sa.Column('profile_photo', sa.String(500), nullable=True),
        sa.Column('designation', sa.String(100), nullable=True),
        sa.Column('department', sa.String(100), nullable=True),
        sa.Column('employee_id', sa.String(50), nullable=True),
        sa.Column('timezone', sa.String(50), nullable=False, server_default='UTC'),
        sa.Column('language', sa.String(10), nullable=False, server_default='en'),
        sa.Column('status', sa.String(20), nullable=False, server_default='active'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('is_verified', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('email_verified_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('phone_verified_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('failed_login_attempts', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('locked_until', sa.DateTime(timezone=True), nullable=True),
        sa.Column('password_changed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('email', name='uq_users_email'),
        sa.UniqueConstraint('username', name='uq_users_username'),
    )
    
    # Create indexes for Users table
    op.create_index('ix_users_email', 'users', ['email'])
    op.create_index('ix_users_username', 'users', ['username'])
    op.create_index('ix_users_is_active', 'users', ['is_active'])
    op.create_index('ix_users_status', 'users', ['status'])
    op.create_index('ix_users_created_at', 'users', ['created_at'])
    
    # Create Sessions table
    op.create_table(
        'sessions',
        sa.Column('id', postgresql.UUID(as_uuid=False), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=False), nullable=False),
        sa.Column('device_id', sa.String(255), nullable=False),
        sa.Column('device_name', sa.String(255), nullable=True),
        sa.Column('ip_address', sa.String(45), nullable=False),
        sa.Column('user_agent', sa.Text(), nullable=False),
        sa.Column('location', sa.String(255), nullable=True),
        sa.Column('refresh_token_jti', sa.String(255), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('last_activity_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('refresh_token_jti', name='uq_sessions_refresh_token_jti'),
    )
    
    # Create indexes for Sessions table
    op.create_index('ix_sessions_user_id', 'sessions', ['user_id'])
    op.create_index('ix_sessions_device_id', 'sessions', ['device_id'])
    op.create_index('ix_sessions_refresh_token_jti', 'sessions', ['refresh_token_jti'])
    op.create_index('ix_sessions_is_active', 'sessions', ['is_active'])
    op.create_index('ix_sessions_expires_at', 'sessions', ['expires_at'])
    
    # Create PasswordHistory table
    op.create_table(
        'password_history',
        sa.Column('id', postgresql.UUID(as_uuid=False), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=False), nullable=False),
        sa.Column('password_hash', sa.String(255), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    
    # Create indexes for PasswordHistory table
    op.create_index('ix_password_history_user_id', 'password_history', ['user_id'])
    
    # Create LoginAttempts table
    op.create_table(
        'login_attempts',
        sa.Column('id', postgresql.UUID(as_uuid=False), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=False), nullable=True),
        sa.Column('email', sa.String(255), nullable=False),
        sa.Column('ip_address', sa.String(45), nullable=False),
        sa.Column('user_agent', sa.Text(), nullable=False),
        sa.Column('success', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('failure_reason', sa.String(100), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    
    # Create indexes for LoginAttempts table
    op.create_index('ix_login_attempts_email', 'login_attempts', ['email'])
    op.create_index('ix_login_attempts_user_id', 'login_attempts', ['user_id'])
    op.create_index('ix_login_attempts_ip_address', 'login_attempts', ['ip_address'])
    op.create_index('ix_login_attempts_created_at', 'login_attempts', ['created_at'])


def downgrade() -> None:
    """Drop authentication tables."""
    
    # Drop indexes
    op.drop_index('ix_login_attempts_created_at', table_name='login_attempts')
    op.drop_index('ix_login_attempts_ip_address', table_name='login_attempts')
    op.drop_index('ix_login_attempts_user_id', table_name='login_attempts')
    op.drop_index('ix_login_attempts_email', table_name='login_attempts')
    
    op.drop_index('ix_password_history_user_id', table_name='password_history')
    
    op.drop_index('ix_sessions_expires_at', table_name='sessions')
    op.drop_index('ix_sessions_is_active', table_name='sessions')
    op.drop_index('ix_sessions_refresh_token_jti', table_name='sessions')
    op.drop_index('ix_sessions_device_id', table_name='sessions')
    op.drop_index('ix_sessions_user_id', table_name='sessions')
    
    op.drop_index('ix_users_created_at', table_name='users')
    op.drop_index('ix_users_status', table_name='users')
    op.drop_index('ix_users_is_active', table_name='users')
    op.drop_index('ix_users_username', table_name='users')
    op.drop_index('ix_users_email', table_name='users')
    
    # Drop constraints
    op.drop_constraint('uq_sessions_refresh_token_jti', 'sessions', type_='unique')
    op.drop_constraint('uq_users_username', 'users', type_='unique')
    op.drop_constraint('uq_users_email', 'users', type_='unique')
    
    # Drop tables
    op.drop_table('login_attempts')
    op.drop_table('password_history')
    op.drop_table('sessions')
    op.drop_table('users')
