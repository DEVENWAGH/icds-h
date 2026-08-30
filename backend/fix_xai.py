
import re

with open("routers/api.py", "r", encoding="utf-8") as f:
    content = f.read()

# 1. Remove simulate_shap
simulate_pattern = """@xai_router.get("/shap/simulate")
def simulate_shap(
    method: str = "shap",
    current_user=Depends(get_current_user)
):
    \"\"\"Compute XAI explanation on a simulated attack scenario.\"\"\"
    from cml.dataset_engine import engine
    event = engine.next_event()
    xai_result = engine.explain_event(event["raw_features"], event["dataset"])
    return {
        **xai_result,
        "risk_score": event["risk_score"],
        "confidence": event["confidence"],
        "prediction_label": event["prediction_label"],
        "dataset": event["dataset"],
        "features_input": event["raw_features"],
        "model_info": engine.get_model_info(event["dataset"]),
        "confidence_band": "High",
        "risk_band": event["severity"],
    }"""

if simulate_pattern in content:
    content = content.replace(simulate_pattern, "")
else:
    print("simulate_shap not found")


# 2. Fix explain_attack_log
old_explain = """@xai_router.get("/explain/{log_id}")
def explain_attack_log(log_id: int, db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    log = db.query(models.AttackLog).filter(models.AttackLog.id == log_id).first()
    if not log or not log.raw_features:
        raise HTTPException(404, "Attack log not found or has no features")
    
    # Infer dataset
    dataset = "TON_IoT"
    if "Phishing" in log.attack_type: dataset = "PhiUSIIL"
    elif "Insider Threat" in log.attack_type: dataset = "CERT"
    
    from cml.dataset_engine import engine
    xai_result = engine.explain_event(log.raw_features, dataset)
    return {
        **xai_result, 
        "attack_log_id": log.id, 
        "attack_type": log.attack_type,
        "dataset": dataset,
        "model_info": engine.get_model_info(dataset)
    }"""

new_explain = """@xai_router.get("/explain/{log_id}")
def explain_attack_log(log_id: int, db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    log = db.query(models.AttackLog).filter(models.AttackLog.id == log_id).first()
    if not log:
        raise HTTPException(404, "AttackLog not found")
        
    if not log.raw_features:
        raise HTTPException(409, "AttackLog has no features")
        
    from sqlalchemy import text
    dataset_source = db.execute(text("SELECT dataset_source FROM attack_logs WHERE id = :id"), {"id": log_id}).scalar()
    
    if not dataset_source:
        raise HTTPException(409, "AttackLog has no dataset_source")
        
    valid_datasets = ["TON_IoT", "PhiUSIIL", "CERT"]
    if dataset_source not in valid_datasets:
        raise HTTPException(400, "Unknown dataset")
        
    from cml.dataset_engine import engine
    from cml.shap_explainer import explainer as shap_explainer
    
    try:
        xai_result = shap_explainer.explain_shap(log.raw_features)
    except Exception as e:
        raise HTTPException(500, f"XAI engine cannot properly explain this dataset-specific event yet: {str(e)}")
        
    return {
        **xai_result, 
        "attack_log_id": log.id, 
        "attack_type": log.attack_type,
        "dataset": dataset_source,
        "raw_features": log.raw_features,
        "model_info": engine.get_model_info(dataset_source)
    }"""

if old_explain in content:
    content = content.replace(old_explain, new_explain)
else:
    print("explain_attack_log not found")


with open("routers/api.py", "w", encoding="utf-8") as f:
    f.write(content)
print("Done")

