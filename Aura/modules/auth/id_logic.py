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
            content = res['text'].lower()
            if any(x in content for x in ["password", "db_pass", "secret_key"]):
                Logger.critical(f"LEAK: {res['url']}")
                findings.append(f"CRITICAL DATA LEAK: {res['url']}")
            else:
                Logger.success(f"Accessible: {res['url']}")
                findings.append(f"Sensitive Path Found: {res['url']}")
    return findings