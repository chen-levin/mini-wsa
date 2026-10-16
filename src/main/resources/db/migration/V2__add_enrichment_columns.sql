ALTER TABLE security_event ADD COLUMN attack_type  VARCHAR(50) NOT NULL;
ALTER TABLE security_event ADD COLUMN threat_score INTEGER     NOT NULL;

CREATE INDEX idx_security_event_client_ip_time ON security_event (client_ip, event_time);
