-- Run this file to create the whole schema in order.
\i 00_extensions.sql
\i 01_schema_and_core_tables.sql
\i 02_mobile_tables.sql
\i 03_search_columns_indexes.sql
\i 04_triggers_and_maintenance.sql
\i 05_functions_search_upsert.sql
\i 06_views.sql

\i 07_export_functions.sql
