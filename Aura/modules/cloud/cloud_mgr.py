from core.logger import Logger
from core.http_utils import build_session


def run_cloud_checks(engine):
    findings = []
    domain = engine.domain
    session = build_session(engine.config)
    candidates = {
        domain,
        domain.replace(".", "-"),
        domain.replace(".", ""),
        f"www-{domain.replace('.', '-')}",
    }

    try:
        import boto3
        from botocore import UNSIGNED
        from botocore.config import Config

        s3 = boto3.client("s3", config=Config(signature_version=UNSIGNED))
        for bucket in sorted(candidates):
            try:
                s3.head_bucket(Bucket=bucket)
                findings.append(f"S3 Bucket Exists: {bucket}")
                try:
                    s3.list_objects_v2(Bucket=bucket, MaxKeys=1)
                    findings.append(f"S3 Bucket Potentially Public/Listable: {bucket}")
                except Exception:
                    pass
            except Exception:
                continue
    except Exception as ex:
        Logger.warn(f"AWS cloud checks skipped/failed: {ex}")

    # GCP GCS and Azure Blob heuristic checks via anonymous HTTP probes.
    for bucket in sorted(candidates):
        try:
            gcs_url = f"https://storage.googleapis.com/{bucket}/"
            gcs = session.get(gcs_url, timeout=session._aura_timeout)
            if gcs.status_code in {200, 403}:
                findings.append(f"GCS Bucket Probe: {bucket} ({gcs.status_code})")
        except Exception:
            pass

        try:
            az_url = f"https://{bucket}.blob.core.windows.net/?comp=list"
            az = session.get(az_url, timeout=session._aura_timeout)
            if az.status_code in {200, 403, 404}:
                findings.append(f"Azure Blob Probe: {bucket} ({az.status_code})")
        except Exception:
            pass

    return findings
