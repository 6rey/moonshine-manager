#!/bin/bash
# Database initialization script for PostgreSQL Docker container
# This script is executed when the PostgreSQL container first starts

set -e

# Get environment variables
POSTGRES_USER=${POSTGRES_USER:-myuser}
POSTGRES_DB=${POSTGRES_DB:-vdi_db}

echo "🔧 Initializing database: $POSTGRES_DB for user: $POSTGRES_USER"

# The database is automatically created by PostgreSQL when the container starts
# with POSTGRES_DB environment variable set. This script ensures the database
# is ready for connections.

# Wait for PostgreSQL to be ready
until pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB"; do
  echo "⏳ Waiting for PostgreSQL to be ready..."
  sleep 2
done

echo "✅ Database $POSTGRES_DB is ready for connections"