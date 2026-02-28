from core.logger import Logger

SENSITIVE_PATHS = [
    "/admin/auth/translation", "/api/v1/config", "/.env", "/config/auth", 
    "/api/users/1", "/v1/debug/vars", "/phpinfo.php"
]

async def check_identity_leaks(engine):
    findings = []
    results = await engine.run_scan(SENSITIVE_PATHS)
    
    for res in results:
        if res and res['status'] == 200:
            msg = f"Found Sensitive Path: {res['url']}"
            if "password" in res['text'].lower() or "db_" in res['text'].lower():
                Logger.critical(f"DATA LEAK: {res['url']}")
                findings.append(f"CRITICAL LEAK: {res['url']}")
            else:
                Logger.success(msg)
                findings.append(msg)
    return findings