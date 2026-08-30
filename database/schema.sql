-- ICDS-H Database Schema
-- Run: mysql -u root -p < database/schema.sql

CREATE DATABASE IF NOT EXISTS icds_h CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE icds_h;

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    full_name VARCHAR(100) NOT NULL,
    email VARCHAR(150) UNIQUE NOT NULL,
    hashed_password VARCHAR(255) NOT NULL,
    role ENUM('admin', 'analyst') DEFAULT 'analyst',
    is_active BOOLEAN DEFAULT TRUE,
    clearance_level INT DEFAULT 1,
    last_login DATETIME,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Hospital Assets table
CREATE TABLE IF NOT EXISTS hospital_assets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    asset_name VARCHAR(100) NOT NULL,
    asset_type VARCHAR(100),
    ip_address VARCHAR(45),
    criticality ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL,
    status ENUM('ONLINE', 'OFFLINE', 'ISOLATED', 'COMPROMISED') DEFAULT 'ONLINE',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Attack logs table
CREATE TABLE IF NOT EXISTS attack_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    attack_type VARCHAR(100) NOT NULL,
    source_ip VARCHAR(45),
    dest_ip VARCHAR(45),
    protocol VARCHAR(20),
    port INT,
    severity ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL,
    status ENUM('DETECTED', 'ANALYZING', 'CONTAINMENT', 'RECOVERY', 'RESOLVED') DEFAULT 'DETECTED',
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
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Alerts table
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
    FOREIGN KEY (acknowledged_by) REFERENCES users(id) ON DELETE SET NULL
);

-- Risk scores table
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
    FOREIGN KEY (attack_log_id) REFERENCES attack_logs(id) ON DELETE SET NULL
);

-- Recommendations table
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
    approved_by INT,
    approved_at DATETIME,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (attack_log_id) REFERENCES attack_logs(id) ON DELETE SET NULL,
    FOREIGN KEY (approved_by) REFERENCES users(id) ON DELETE SET NULL
);

-- Recovery actions table
CREATE TABLE IF NOT EXISTS recovery_actions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    recommendation_id INT,
    action_name VARCHAR(255) NOT NULL,
    action_type ENUM('ISOLATE', 'BLOCK', 'RESTORE', 'RESET', 'PATCH') NOT NULL,
    target_node VARCHAR(100),
    status ENUM('PENDING', 'IN_PROGRESS', 'COMPLETED', 'FAILED') DEFAULT 'PENDING',
    executed_by INT,
    execution_log TEXT,
    started_at DATETIME,
    completed_at DATETIME,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (recommendation_id) REFERENCES recommendations(id) ON DELETE SET NULL,
    FOREIGN KEY (executed_by) REFERENCES users(id) ON DELETE SET NULL
);

-- Incidents table
CREATE TABLE IF NOT EXISTS incidents (
    id INT AUTO_INCREMENT PRIMARY KEY,
    attack_id INT,
    status ENUM('DETECTED', 'ANALYZING', 'CONTAINMENT', 'RECOVERY', 'RESOLVED') DEFAULT 'DETECTED',
    assigned_to INT,
    mitre_technique_id VARCHAR(50),
    mitre_technique_name VARCHAR(150),
    opened_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    closed_at DATETIME,
    FOREIGN KEY (attack_id) REFERENCES attack_logs(id) ON DELETE SET NULL,
    FOREIGN KEY (assigned_to) REFERENCES users(id) ON DELETE SET NULL
);

-- Monitoring history table
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

-- QIGA Results table
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

-- Attack Memory table
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

-- Seed default admin user (password: Admin@1234)
INSERT INTO users (full_name, email, hashed_password, role, clearance_level)
VALUES ('Dr. Aris Thorne', 'admin@icds-h.com',
  '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewRrBVhzPKvZfSwu',
  'admin', 5)
ON DUPLICATE KEY UPDATE id=id;

-- Seed sample hospital assets
INSERT INTO hospital_assets (asset_name, asset_type, ip_address, criticality, status) VALUES
('Oncology Database EMR', 'EMR Server', '10.0.0.20', 'CRITICAL', 'ONLINE'),
('Radiology PACS Server', 'Imaging System', '10.0.0.21', 'HIGH', 'ONLINE'),
('Lab Pathology Cluster', 'Laboratory Server', '10.0.0.22', 'HIGH', 'ONLINE'),
('ICU Vital Monitor Node-04', 'ICU Vital Monitoring', '10.0.0.23', 'CRITICAL', 'ONLINE'),
('Hospital Public Web App', 'Web Application', '10.0.0.5', 'MEDIUM', 'ONLINE'),
('Active Directory Auth', 'Authentication Service', '10.0.0.1', 'CRITICAL', 'ONLINE');
