-- Create the Keycloak database (app DB 'nids' is created via MARIADB_DATABASE env var)
CREATE DATABASE IF NOT EXISTS keycloak CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
GRANT ALL PRIVILEGES ON keycloak.* TO 'nids'@'%';

-- Create Infisical database (Phase 3: centralized secrets management)
CREATE DATABASE IF NOT EXISTS infisical CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
GRANT ALL PRIVILEGES ON infisical.* TO 'nids'@'%';

FLUSH PRIVILEGES;
