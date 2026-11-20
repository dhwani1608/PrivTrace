# Deploying PrivTrace on Google Cloud

Target layout (not deployed yet — this is the guide):

```
Cloud Run service  privtrace-api   (FastAPI, also serves report HTML/JSON)
Cloud Run service  privtrace-ui    (nginx + built React app, proxies /api)
Cloud Run Job      privtrace-scan  (runs one scan per execution; same image as the API)
Cloud SQL          Postgres 16     (scan records + redacted results)
Memorystore        Redis           (optional: progress fan-out / rate limiting)
Secret Manager     GEMINI_API_KEY, DB password
```

Region: prefer `asia-south1` (Mumbai) or `asia-south2` (Delhi) so customer code and results stay in India (relevant to DPDP s.16 and CERT-In log localisation).

## 1. One-time setup

```bash
PROJECT=my-project REGION=asia-south1
gcloud config set project $PROJECT
gcloud services enable run.googleapis.com sqladmin.googleapis.com redis.googleapis.com \
  secretmanager.googleapis.com artifactregistry.googleapis.com cloudbuild.googleapis.com
gcloud artifacts repositories create privtrace --repository-format=docker --location=$REGION
```

## 2. Data stores

```bash
gcloud sql instances create privtrace-db --database-version=POSTGRES_16 --region=$REGION \
  --tier=db-custom-1-3840 --storage-auto-increase
gcloud sql databases create privtrace --instance=privtrace-db
gcloud sql users create privtrace --instance=privtrace-db --password="$(openssl rand -base64 24)"

gcloud redis instances create privtrace-cache --size=1 --region=$REGION   # optional
```

## 3. Secrets

```bash
printf '%s' "$GEMINI_KEY" | gcloud secrets create gemini-api-key --data-file=-
printf '%s' "postgresql+psycopg://privtrace:PASSWORD@/privtrace?host=/cloudsql/$PROJECT:$REGION:privtrace-db" \
  | gcloud secrets create privtrace-database-url --data-file=-
```

## 4. Build images

```bash
IMG=$REGION-docker.pkg.dev/$PROJECT/privtrace
gcloud builds submit --tag $IMG/api:latest --file backend/Dockerfile .      # build context = repo root
gcloud builds submit --tag $IMG/ui:latest frontend
```

(For the UI on Cloud Run, change `proxy_pass http://api:8000` in `frontend/nginx.conf` to the API service URL, or serve the UI from the same origin via a load balancer.)

## 5. API service

```bash
gcloud run deploy privtrace-api --image $IMG/api:latest --region $REGION \
  --add-cloudsql-instances $PROJECT:$REGION:privtrace-db \
  --set-secrets DATABASE_URL=privtrace-database-url:latest,GEMINI_API_KEY=gemini-api-key:latest \
  --set-env-vars GEMINI_MODEL=<model-id>,PRIVTRACE_CORS_ORIGINS='["https://<ui-url>"]' \
  --memory 2Gi --cpu 2 --timeout 900 --no-allow-unauthenticated
```

`GEMINI_MODEL` is configuration — pick the current Gemini model id at deploy time.

## 6. Scans as Cloud Run Jobs

In the MVP the API runs scans as FastAPI background tasks. For production, move them to a job so long scans don't hold an API instance:

```bash
gcloud run jobs create privtrace-scan --image $IMG/api:latest --region $REGION \
  --add-cloudsql-instances $PROJECT:$REGION:privtrace-db \
  --set-secrets DATABASE_URL=privtrace-database-url:latest,GEMINI_API_KEY=gemini-api-key:latest \
  --set-env-vars GEMINI_MODEL=<model-id> --task-timeout 1800 --max-retries 0 \
  --command python --args=-c,"import os,sys; from privtrace.api.jobs import run_job; from privtrace.db.session import get_sessionmaker; run_job(get_sessionmaker(), os.environ['SCAN_ID'])"
```

The API then creates the `ScanRecord` and starts an execution with `SCAN_ID` overridden (`gcloud run jobs execute privtrace-scan --update-env-vars SCAN_ID=...` or the Run Admin API). `run_job()` is the same function the API uses today; it fetches code into a temp dir, scans, stores the redacted result and deletes the code. ZIP uploads would first be written to a Cloud Storage bucket with a 1-day lifecycle rule and read by the job.

## 7. Hardening checklist

- Cloud Run ingress `internal-and-cloud-load-balancing` + IAP or your auth in front of the API.
- No customer code is persisted: workspaces are temp dirs inside the container and deleted after each scan; Cloud Run's in-memory filesystem disappears with the instance.
- Logs: the API installs a redacting log filter; set a Cloud Logging bucket in an India region with ≥ 180-day retention if you are subject to CERT-In.
- Gemini: only redacted ≤ 40-line snippets are sent (see `ai/gateway.py`); review the vendor's data-use terms and region.
