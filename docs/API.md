# ICDS-H API Documentation

Base URL: `http://localhost:8000`  
Interactive Docs: `http://localhost:8000/docs`

## Authentication
All `/api/*` endpoints require: `Authorization: Bearer <token>`

### POST /api/auth/login
```json
{ "email": "admin@icds-h.com", "password": "Admin@1234" }
```
Returns: `{ access_token, token_type, user }`

### POST /api/auth/register
```json
{ "full_name": "Dr. Smith", "email": "dr@hospital.com", "password": "pass", "role": "analyst" }
```

### GET /api/auth/me
Returns current user info.

---

## Attack Logs
- `GET /api/logs/` — List logs (`?severity=CRITICAL&limit=50`)
- `GET /api/logs/stats` — Count by severity/status

## Alerts
- `GET /api/alerts/` — List alerts
- `GET /api/alerts/unacknowledged/count` — Unread count
- `PATCH /api/alerts/{id}/acknowledge` — Acknowledge alert

## Risk Prediction
- `POST /api/predict/` — Run MLP prediction (body: PredictInput)
- `GET /api/predict/latest` — Last 10 risk scores
- `GET /api/predict/simulate` — Random demo prediction

**PredictInput schema:**
```json
{
  "source_ip": "192.168.1.1",
  "protocol": "TCP",
  "port": 80,
  "packet_size": 500.0,
  "request_frequency": 10.0,
  "duration": 0.5,
  "bytes_sent": 5000.0,
  "bytes_received": 8000.0
}
```

## Recommendations
- `GET /api/recommendations/` — List recommendations
- `PATCH /api/recommendations/{id}/approve` — Authorize mitigation

## Monitoring
- `GET /api/monitoring/live` — Simulated live metrics
- `GET /api/monitoring/history` — Historical monitoring data

## Admin (admin role required)
- `GET /api/admin/users` — All users
- `GET /api/admin/stats` — System stats

## WebSocket
- `ws://localhost:8000/ws/live` — Live events stream

**Message types:**
```json
{ "type": "monitoring", "data": { "throughput_gbps": 1.3, "latency_ms": 12, ... } }
{ "type": "threat", "data": { "attack_type": "DDoS", "severity": "CRITICAL", ... } }
```
