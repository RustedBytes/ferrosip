#!/bin/bash
# From sipcapture/homer7-docker (heplify-server/hom7-timescaledb-all):
# homer-app keeps its settings and users in homer_config; heplify-server
# creates homer_data and its tables itself. Runs on the first start only.
set -euo pipefail

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
	CREATE DATABASE homer_config;
EOSQL
