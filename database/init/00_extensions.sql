-- PostgreSQL >= 16
-- Required extensions for UUIDs, trigram search, and flexible indexing
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS btree_gin;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
