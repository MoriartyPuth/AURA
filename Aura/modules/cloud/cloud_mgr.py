from core.logger import Logger
from core.http_utils import build_session
from core.parallel import http_workers, pmap


def run_cloud_checks(engine):
    findings = []
    if not engine.config.get("scope", {}).get("allow_cloud_bucket_probes", True):
        Logger.warn("Cloud bucket probes disabled by scope.allow_cloud_bucket_probes.")
        return findings
    # NOTE: guessed bucket names live on third-party infrastructure (AWS/GCP/Azure)
    # and may not belong to the target - disable via config if your program forbids it.
    domain = engine.domain
    session = build_session(engine.config)
    candidates = {
        domain,
        domain.replace(".", "-"),
        domain.replace(".", ""),
        f"www-{domain.replace('.', '-')}",
    }

    workers = http_workers(engine.config)
    buckets = sorted(candidates)

    try:
        import boto3
        from botocore import UNSIGNED
        from botocore.config import Config

        s3 = boto3.client("s3", config=Config(signature_version=UNSIGNED))  # clients are thread-safe

        def s3_probe(bucket):
            out = []
            try:
                s3.head_bucket(Bucket=bucket)
            except Exception:
                return out
            out.append(f"S3 Bucket Exists: {bucket}")
            try:
                s3.list_objects_v2(Bucket=bucket, MaxKeys=1)
                out.append(f"S3 Bucket Potentially Public/Listable: {bucket}")
            except Exception:
                pass
            return out

        for res in pmap(s3_probe, buckets, workers):
            findings.extend(res)
    except Exception as ex:
        Logger.warn(f"AWS cloud checks skipped/failed: {ex}")

    # GCP GCS and Azure Blob heuristic checks via anonymous HTTP probes.
    def http_probe(job):
        kind, bucket = job
        try:
            if kind == "gcs":
                r = session.get(f"https://storage.googleapis.com/{bucket}/")
                if r.status_code in {200, 403}:
                    return f"GCS Bucket Probe: {bucket} ({r.status_code})"
            else:
                r = session.get(f"https://{bucket}.blob.core.windows.net/?comp=list")
                if r.status_code in {200, 403, 404}:
                    return f"Azure Blob Probe: {bucket} ({r.status_code})"
        except Exception:
            pass
        return None

    jobs = [(kind, b) for b in buckets for kind in ("gcs", "azure")]
    findings.extend(f for f in pmap(http_probe, jobs, workers) if f)
    return findings
