-- ICDS-H Database Schema
-- Run: mysql -u root -p < database/schema.sql

CREATE DATABASE IF NOT EXISTS icds_h CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE icds_h;

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    full_name VARCHAR(100),
    email VARCHAR(150) UNIQUE NOT NULL,
    hashed_password VARCHAR(255) NOT NULL,
    role ENUM('admin', 'analyst', 'clinical') DEFAULT 'analyst',
    is_active BOOLEAN DEFAULT TRUE,
    clearance_level INT DEFAULT 1,
    last_login DATETIME,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_users_email (email),
    INDEX idx_users_role (role)
);

CREATE TABLE IF NOT EXISTS hospital_assets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    asset_name VARCHAR(100) NOT NULL,
    asset_type VARCHAR(100),
    ip_address VARCHAR(45),
    criticality ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL,
    status ENUM('ONLINE', 'OFFLINE', 'ISOLATED', 'COMPROMISED') DEFAULT 'ONLINE',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_assets_status (status)
);

CREATE TABLE IF NOT EXISTS attack_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    attack_type VARCHAR(100) NOT NULL,
    source_ip VARCHAR(45),
    dest_ip VARCHAR(45),
    protocol VARCHAR(20),
    port INT,
    severity ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL,
    status ENUM('DETECTED', 'ACKNOWLEDGED', 'ANALYZING', 'CONTAINMENT', 'RECOVERY', 'RESOLVED') DEFAULT 'DETECTED',
    suspicious_score FLOAT DEFAULT 0.0,
    mitre_technique_id VARCHAR(50),
    mitre_technique_name VARCHAR(150),
    raw_features JSON,
    description TEXT,
    dataset_source VARCHAR(100),
    cpu_utilization FLOAT,
    failed_login_count INT,
    malware_indicator BOOLEAN DEFAULT FALSE,
    access_pattern_score FLOAT,
    user_behavior_score FLOAT,
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at DATETIME,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_attack_status (status),
    INDEX idx_attack_type (attack_type),
    INDEX idx_attack_detected (detected_at)
);

CREATE TABLE IF NOT EXISTS alerts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    alert_type VARCHAR(100) NOT NULL,
    title VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,
    severity ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL,
    is_acknowledged BOOLEAN DEFAULT FALSE,
    attack_log_id INT,
    acknowledged_by INT,
    acknowledged_at DATETIME,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (attack_log_id) REFERENCES attack_logs(id) ON DELETE SET NULL,
    FOREIGN KEY (acknowledged_by) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_alerts_ack (is_acknowledged),
    INDEX idx_alerts_severity (severity)
);

CREATE TABLE IF NOT EXISTS risk_scores (
    id INT AUTO_INCREMENT PRIMARY KEY,
    score FLOAT NOT NULL,
    confidence FLOAT NOT NULL,
    confidence_band VARCHAR(20),
    risk_band VARCHAR(20),
    model_version VARCHAR(50),
    features_used JSON,
    prediction_label VARCHAR(100),
    node_id VARCHAR(50),
    status ENUM('STABLE', 'WARNING', 'CRITICAL') DEFAULT 'STABLE',
    shap_values JSON,
    attack_log_id INT,
    computed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (attack_log_id) REFERENCES attack_logs(id) ON DELETE SET NULL,
    INDEX idx_risk_computed (computed_at)
);

CREATE TABLE IF NOT EXISTS recommendations (
    id INT AUTO_INCREMENT PRIMARY KEY,
    attack_log_id INT,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    action_type VARCHAR(100),
    confidence_score FLOAT,
    resource_cost VARCHAR(50),
    latency_impact VARCHAR(50),
    is_approved BOOLEAN DEFAULT FALSE,
    status VARCHAR(20) DEFAULT 'PENDING',
    rank INT DEFAULT 1,
    approved_by INT,
    approved_at DATETIME,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (attack_log_id) REFERENCES attack_logs(id) ON DELETE SET NULL,
    FOREIGN KEY (approved_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS recovery_actions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    recommendation_id INT,
    action_name VARCHAR(255) NOT NULL,
    action_type ENUM('ISOLATE', 'BLOCK', 'RESTORE', 'RESET', 'PATCH', 'WAF_RULE', 'MONITOR_ENHANCED') NOT NULL,
    target_node VARCHAR(100),
    status ENUM('PENDING', 'IN_PROGRESS', 'COMPLETED', 'FAILED') DEFAULT 'PENDING',
    progress_percent INT DEFAULT 0,
    current_step VARCHAR(255),
    executed_by INT,
    execution_log TEXT,
    started_at DATETIME,
    completed_at DATETIME,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (recommendation_id) REFERENCES recommendations(id) ON DELETE SET NULL,
    FOREIGN KEY (executed_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS incidents (
    id INT AUTO_INCREMENT PRIMARY KEY,
    attack_id INT,
    status ENUM('DETECTED', 'ACKNOWLEDGED', 'ANALYZING', 'CONTAINMENT', 'RECOVERY', 'RESOLVED') DEFAULT 'DETECTED',
    assigned_to INT,
    mitre_technique_id VARCHAR(50),
    mitre_technique_name VARCHAR(150),
    opened_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    closed_at DATETIME,
    FOREIGN KEY (attack_id) REFERENCES attack_logs(id) ON DELETE SET NULL,
    FOREIGN KEY (assigned_to) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_incident_status (status)
);

CREATE TABLE IF NOT EXISTS monitoring_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    throughput_gbps FLOAT,
    packet_loss FLOAT,
    latency_ms FLOAT,
    active_connections INT,
    node_load_avg FLOAT,
    sys_health FLOAT,
    mlp_model_status VARCHAR(50),
    quantum_optimizer_status VARCHAR(50),
    recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS qiga_results (
    id INT AUTO_INCREMENT PRIMARY KEY,
    attack_log_id INT,
    risk_score FLOAT,
    attack_type VARCHAR(100),
    severity VARCHAR(20),
    objective_score FLOAT,
    selected_actions JSON,
    all_actions_scored JSON,
    convergence_data JSON,
    combined_effectiveness FLOAT,
    combined_cost INT,
    total_downtime_min INT,
    alpha FLOAT DEFAULT 0.4,
    beta FLOAT DEFAULT 0.35,
    gamma FLOAT DEFAULT 0.25,
    generations INT,
    population_size INT,
    computed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (attack_log_id) REFERENCES attack_logs(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS attack_memory (
    id INT AUTO_INCREMENT PRIMARY KEY,
    attack_log_id INT,
    attack_type VARCHAR(100),
    severity VARCHAR(20),
    risk_score FLOAT,
    feature_fingerprint JSON,
    raw_features JSON,
    recommended_actions JSON,
    outcome VARCHAR(50),
    success BOOLEAN DEFAULT FALSE,
    recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (attack_log_id) REFERENCES attack_logs(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS firewall_rules (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45),
    port INT,
    protocol VARCHAR(20),
    direction VARCHAR(10) DEFAULT 'INBOUND',
    reason VARCHAR(255),
    attack_type VARCHAR(100),
    severity VARCHAR(20),
    attack_log_id INT,
    blocked_by VARCHAR(100) DEFAULT 'SYSTEM',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME,
    FOREIGN KEY (attack_log_id) REFERENCES attack_logs(id) ON DELETE SET NULL,
    INDEX idx_fw_ip (ip_address),
    INDEX idx_fw_active (is_active)
);

CREATE TABLE IF NOT EXISTS anomaly_detections (
    id INT AUTO_INCREMENT PRIMARY KEY,
    attack_log_id INT,
    anomaly_score FLOAT,
    is_anomaly BOOLEAN DEFAULT FALSE,
    detector_type VARCHAR(50) DEFAULT 'IsolationForest',
    dataset_source VARCHAR(100),
    features_used JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (attack_log_id) REFERENCES attack_logs(id) ON DELETE SET NULL
);

INSERT INTO hospital_assets (asset_name, asset_type, ip_address, criticality, status) VALUES
('Oncology Database EMR', 'EMR Server', '10.0.0.20', 'CRITICAL', 'ONLINE'),
('Radiology PACS Server', 'Imaging System', '10.0.0.21', 'HIGH', 'ONLINE'),
('Lab Pathology Cluster', 'Laboratory Server', '10.0.0.22', 'HIGH', 'ONLINE'),
('ICU Vital Monitor Node-04', 'ICU Vital Monitoring', '10.0.0.23', 'CRITICAL', 'ONLINE'),
('Hospital Public Web App', 'Web Application', '10.0.0.5', 'MEDIUM', 'ONLINE'),
('Active Directory Auth', 'Authentication Service', '10.0.0.1', 'CRITICAL', 'ONLINE');
