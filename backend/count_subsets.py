import sys; sys.path.append('.'); from cml.dataset_engine import engine;
print('TON_normal:', len(engine.ton_normal))
print('TON_ddos:', len(engine.ton_ddos))
print('TON_ransomware:', len(engine.ton_ransomware))
print('PHI_normal:', len(engine.phi_normal))
print('PHI_phishing:', len(engine.phi_phishing))
print('CERT_normal:', len(engine.cert_normal))
print('CERT_insider:', len(engine.cert_insider))
