"""Add status column to users table

Revision ID: add_status_column
Revises: 70b16dc3ef77
Create Date: 2025-03-13 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'add_status_column'
down_revision = '70b16dc3ef77'
branch_labels = None
depends_on = None

def upgrade():
    # Add the status column with a default value of 'pending'
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('status', sa.String(length=20), nullable=False, server_default='pending'))

def downgrade():
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_column('status')
