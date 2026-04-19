#!/bin/bash
# Creates the limited-privilege tusshare app user on first postgres startup.
# Mounted at /docker-entrypoint-initdb.d/ — runs once on a fresh volume only.
#
# Requires TUSSHARE_PG_PASSWORD to be set in the postgres container environment.
# The tusshare user is NOT a superuser: it can manage data in this database
# but cannot create roles or other databases (privileges the bootstrap needs).
# citext is a trusted extension in PostgreSQL 13+ so the app user can install it.
set -e

APP_USER="${TUSSHARE_APP_USER:-tusshare}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
    -v app_user="$APP_USER" \
    -v app_db="$POSTGRES_DB" \
    -v app_password="$TUSSHARE_PG_PASSWORD" <<-'EOSQL'
    CREATE USER :"app_user" WITH PASSWORD :'app_password';
    GRANT ALL PRIVILEGES ON DATABASE :"app_db" TO :"app_user";
    GRANT ALL ON SCHEMA public TO :"app_user";
    ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO :"app_user";
    ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO :"app_user";
EOSQL
