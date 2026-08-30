from database import engine, SessionLocal
from sqlalchemy import text

def update_enums():
    with engine.connect() as conn:
        print("Updating attack_logs status enum...")
        conn.execute(text("ALTER TABLE attack_logs MODIFY COLUMN status VARCHAR(50)"))
        conn.execute(text("UPDATE attack_logs SET status = 'DETECTED'"))
        conn.execute(text("ALTER TABLE attack_logs MODIFY COLUMN status ENUM('DETECTED', 'ANALYZING', 'CONTAINMENT', 'RECOVERY', 'RESOLVED') DEFAULT 'DETECTED'"))
        
        print("Updating incidents status enum...")
        conn.execute(text("ALTER TABLE incidents MODIFY COLUMN status VARCHAR(50)"))
        conn.execute(text("UPDATE incidents SET status = 'DETECTED'"))
        conn.execute(text("ALTER TABLE incidents MODIFY COLUMN status ENUM('DETECTED', 'ANALYZING', 'CONTAINMENT', 'RECOVERY', 'RESOLVED') DEFAULT 'DETECTED'"))
        
        conn.commit()
        print("Done.")

if __name__ == "__main__":
    update_enums()
