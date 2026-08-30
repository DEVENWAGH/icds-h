# ICDS-H: Intelligent Cyber Defense System for Healthcare

> AI-powered healthcare cybersecurity detection, prevention, and recovery platform.

---

## Project Structure

```
icds-h/
├── frontend/               # React + Vite + Tailwind
│   ├── src/
│   │   ├── components/     # Reusable UI components
│   │   ├── pages/          # Route pages
│   │   ├── hooks/          # Custom React hooks
│   │   ├── utils/          # API calls, helpers
│   │   └── store/          # Zustand global state
│   ├── index.html
│   ├── vite.config.js
│   ├── tailwind.config.js
│   └── package.json
├── backend/                # FastAPI Python backend
│   ├── main.py
│   ├── config.py
│   ├── database.py
│   ├── routers/            # API route modules
│   ├── models/             # SQLAlchemy DB models
│   ├── schemas/            # Pydantic schemas
│   ├── ml/                 # ML model & training
│   └── requirements.txt
├── database/
│   └── schema.sql          # MySQL schema
├── dataset/
│   └── README_dataset.md   # CICIDS2017 instructions
└── docs/
    └── API.md              # API documentation
```

---

## Quick Start

### Prerequisites
- Node.js 18+
- Python 3.10+
- MySQL 8.0+

### 1. Database Setup
```bash
mysql -u root -p < database/schema.sql
```

### 2. Backend Setup
```bash
cd backend
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your MySQL credentials

# Train the ML model (first time)
python ml/train_model.py

# Start backend
uvicorn main:app --reload --port 8000
```

### 3. Frontend Setup
```bash
cd frontend
npm install
npm run dev
```

Frontend runs at: http://localhost:5173  
Backend API: http://localhost:8000  
API Docs: http://localhost:8000/docs  

---

## Default Login
- **Email:** admin@icds-h.com  
- **Password:** Admin@1234

---

## Dataset: CICIDS2017
Download from: https://www.unb.ca/cic/datasets/ids-2017.html  
Place CSV files in `dataset/raw/`  
Then run: `python backend/ml/preprocess.py`

---

## Pages
| Page | Route |
|------|-------|
| Landing | `/` |
| Login | `/login` |
| Dashboard | `/dashboard` |
| Monitoring | `/monitoring` |
| Analytics | `/analytics` |
| Alerts | `/alerts` |
| Logs | `/logs` |
| XAI | `/xai` |
| Response | `/response` |
| Admin | `/admin` |
| Reports | `/reports` |

---

## Tech Stack
- **Frontend:** React 18, Vite, Tailwind CSS, Recharts, Socket.IO Client
- **Backend:** FastAPI, SQLAlchemy, JWT, WebSocket
- **Database:** MySQL 8
- **AI/ML:** Scikit-learn MLP, Pandas, NumPy
- **Dataset:** CICIDS2017
