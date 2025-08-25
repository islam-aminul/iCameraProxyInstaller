-- Simple application setup
CREATE TABLE IF NOT EXISTS app_info (
    id INTEGER IDENTITY PRIMARY KEY,
    install_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    version VARCHAR(50) DEFAULT '1.0.0',
    status VARCHAR(20) DEFAULT 'INSTALLED'
);

INSERT INTO app_info (install_date, version, status) VALUES (CURRENT_TIMESTAMP, '1.0.0', 'INSTALLED');