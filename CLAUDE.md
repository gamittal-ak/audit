# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Running the Application

```bash
# Start all services (Redis, FastAPI, Celery worker, Nginx)
docker compose up --build

# Start in detached mode
docker compose up -d --build

# View logs
docker compose logs -f

# Stop all services
docker compose down
```

The app is accessible at `http://localhost:8281` via Nginx reverse proxy.

## Development (without Docker)

```bash
# Install dependencies
pip install -r requirements.txt

# Copy and configure environment
cp .env.example .env

# Run FastAPI dev server
uvicorn app.main:app --reload --port 8000

# Run Celery worker (separate terminal, requires Redis running)
celery -A app.tasks.celery_app worker --concurrency=2 --loglevel=info
```

## Architecture Overview

**Request flow:**
1. Nginx (`:8281`) → FastAPI (`:8000`) for all requests
2. User authenticates with password → session cookie set
3. Report request → `POST /api/reports` → Celery task queued in Redis
4. UI polls `GET /api/reports/{task_id}/status` until complete
5. Report files (`.xlsx` + `.json`) written to `reports/` volume

**Key architectural decisions:**
- No database — Redis stores task metadata/status; filesystem stores report files
- Auth is a single shared password (`APP_PASSWORD`), checked in `app/auth.py` via `@requires_auth` decorator
- Akamai API calls use async `httpx` with a `asyncio.Semaphore` concurrency limit (`CONCURRENCY_LIMIT` env var)
- EdgeGrid HMAC-SHA256 auth is implemented as an `httpx.Auth` subclass in `services/edgegrid_auth.py`
- Rule tree caching in Redis (`RULE_TREE_CACHE_TTL` seconds) to avoid redundant Akamai API calls

**Component responsibilities:**
- `app/main.py` — FastAPI app init, middleware, template/static mounts, router registration
- `app/routers/` — Thin HTTP handlers; delegate to services/tasks
- `app/services/akamai_client.py` — All Akamai PAPI/Reporting API calls
- `app/services/property_analysis.py` — Pure analysis functions (no I/O); detects advanced overrides, custom behaviors, Site Shield, SRO, CloudWrapper
- `app/tasks/report_task.py` — Celery task orchestrating the full audit: fetch properties → analyze → write Excel/JSON
- `app/services/excel_service.py` — Excel report generation (openpyxl/xlsxwriter)

## Configuration

All config is in `.env` (see `.env.example`). Key variables:
- `APP_PASSWORD` — login password for the web UI
- `EDGERC_PATH` — path to Akamai `.edgerc` credentials file (mounted as Docker secret)
- `EDGERC_SECTION` — section name within `.edgerc` (default: `default` for all API calls except Reporting API)
- `EDGERC_REPORTING_SECTION` — section name within `.edgerc` specifically for Reporting API calls (default: `reporting`)
- `CONCURRENCY_LIMIT` — max parallel Akamai API requests per task
- `RULE_TREE_CACHE_TTL` — Redis cache TTL in seconds for rule trees
- `REPORTS_BASE_DIR` — filesystem path where report files are written

## Troubleshooting and Debugging

This section outlines common issues and provides guidance for debugging the application.

### Issue 1: Reporting API numbers are not populating.

**Analysis:**

The `reporting API` numbers are populated by fetching traffic data using the `reporting_client` (an instance of `AkamaiClient`) in the `_process_property` function within `app/tasks/report_task.py`. The actual API call is made by the `get_traffic` method in `app/services/akamai_client.py`.

The most likely cause for numbers not populating is an issue with the Reporting API call or its response.

**Key areas for investigation:**

1.  **`app/services/akamai_client.py` (`get_traffic` method):**
    *   **403 Forbidden Errors:** The `get_traffic` method explicitly checks for a `403 Forbidden` status code from the Reporting API. If received, the `switch_key` (account) is added to a `_reporting_forbidden` set, and an empty data set is returned. This prevents further attempts for that account, leading to no numbers populating.
    *   **Other API Errors:** Any non-200 status code will be logged as a warning, and an `httpx.HTTPStatusError` will be raised, halting data retrieval for that specific API call.
    *   **Empty `data` field:** The Reporting API might return a 200 OK response but with an empty `"data"` array, indicating no traffic data available for the requested parameters (e.g., cpcodes, time range).

2.  **`app/tasks/report_task.py` (`_async_run_report` and `_process_property` functions):**
    *   **`.edgerc` Configuration:** The project uses two sections in the `.edgerc` file:
        *   A `default` section for all Akamai API interactions except reporting.
        *   A `reporting` section specifically for Reporting API calls.
        If the `reporting` section in the `.edgerc` file is misconfigured, missing, or points to credentials without the necessary permissions for the Reporting API, authentication will fail, leading to 403 errors.
    *   **Missing CP Codes:** The `get_traffic` method requires a list of `cpcodes`. If `all_cpcodes_flat` (derived from the rule tree analysis) is empty for a property, no traffic data will be requested, and thus no numbers will populate.

**Recommended Actions:**

-   **Verify `.edgerc` credentials:** Ensure the `reporting` section in your `.edgerc` file has valid API credentials with appropriate access to the Akamai Reporting API. Also, ensure the `default` section is correctly configured for other API calls.
-   **Check API client permissions:** Confirm that the API client associated with the credentials has the necessary permissions to retrieve reporting data for the accounts in question.
-   **Examine logs:** Look for `logger.warning` and `logger.exception` messages related to the Reporting API in the application logs, especially for "Reporting API 403" or other status codes.
-   **Inspect `final_report` JSON:** After a report run, examine the generated JSON file (`json_path`) to see if the `traffic` data is present within the `cpcodes` sections of the properties. This will indicate if the data was successfully retrieved from the API before Excel generation.

---

### Issue 2: The excel report that we download is not matching the correct fields with values.

**Analysis:**

The Excel report is generated by the `generate_excel` function in `app/services/excel_service.py`, which consumes the `final_report` JSON output from `app/tasks/report_task.py`. The structure and content of the Excel file are determined by the `_HEADERS` list and the data extraction logic within `generate_excel` and its helper functions (`_prop_base`, `_expand_cpcodes`, `_hostname_cols`).

**Key areas for investigation:**

1.  **`app/services/excel_service.py` (`_HEADERS` list and data extraction logic):**
    *   **Header-Data Mismatch:** The `_HEADERS` list defines the expected columns. If the data within the `final_report` JSON does not align with these headers, or if the keys used in `_prop_base`, `_expand_cpcodes`, and `_hostname_cols` to extract values do not match the actual keys in the JSON, then fields will appear empty or incorrect in the Excel, which might be perceived as "not matching."
    *   **Default Values:** Many `.get("key", "")` or `.get("key") or []` calls are used. If a key is missing in the JSON, these will result in empty strings or lists in the Excel, which might be perceived as "not matching."
    *   **Complex Data Structures:** Functions like `_expand_cpcodes` and `_hostname_cols` process nested data. Any inconsistencies or unexpected structures in the `cpcodes` or `hostnames` data within the `final_report` JSON could lead to incorrect values or formatting in the Excel. For example, `_expand_cpcodes` expects `ids`, `descs`, and `prods` to be lists; if they are not, the logic might not extract data as expected.

2.  **`app/tasks/report_task.py` (JSON report generation):**
    *   **Incomplete `final_report` JSON:** If data fetching from Akamai APIs fails or returns incomplete results during the `_process_property` stage (as described in Issue 1), the `final_report` JSON will itself be missing data. This will directly translate to missing or incorrect fields in the Excel report, as `generate_excel` can only work with the data it receives.

**Recommended Actions:**

-   **Compare JSON to Excel:** Obtain a generated JSON report (`.json`) and its corresponding Excel report (`.xlsx`). Manually compare the values in the JSON with the values in the Excel to pinpoint exact discrepancies.
-   **Trace data flow:** For specific fields that are incorrect, trace back through `_prop_base`, `_expand_cpcodes`, or `_hostname_cols` in `app/services/excel_service.py` to see how the data is being extracted from the JSON. Then, trace further back to `_process_property` in `app/tasks/report_task.py` to see how that data is being assembled into the JSON.
-   **Verify input data for `generate_excel`:** Ensure the `final_report` JSON contains all the expected keys and values that `excel_service.py` is attempting to extract. If the JSON itself is missing data, the problem originates earlier in the report generation pipeline.
-   **Inspect `_HEADERS`:** Double-check if the `_HEADERS` list in `app/services/excel_service.py` accurately reflects the desired columns and their order.



## Deployment to Production (Linode)

To deploy the application and any code changes to your Linode server (e.g., `172.233.138.166:8281`), follow these steps:

1.  **Transfer updated files:**
    Transfer all updated code files, including `CLAUDE.md`, from your local machine to the Linode server. You can use `scp` or `rsync` for this. Replace `<user>` with your Linode username and `/path/to/your/akamai-audit-web` with the actual path to your project directory on the server.

    ```bash
    # Example using scp for a single file
    scp c:\Users\gamittal\Documents\akamai-audit-web\CLAUDE.md <user>@172.233.138.166:/path/to/your/akamai-audit-web/CLAUDE.md

    # Example using rsync for the entire project directory (ensure you exclude sensitive files like .env)
    rsync -avz --exclude '.env' c:\Users\gamittal\Documents\akamai-audit-web/ <user>@172.233.138.166:/path/to/your/akamai-audit-web/
    ```

2.  **Log in to your Linode server:**
    ```bash
    ssh <user>@172.233.138.166
    ```

3.  **Navigate to your project directory** on the Linode server.

4.  **Rebuild and redeploy Docker services:**
    To ensure all changes are incorporated, you need to stop and remove the old Docker containers, and then rebuild the images before starting them again.

    ```bash
    # Stop and remove existing containers, networks, and volumes
    docker compose down

    # Build (or rebuild) services and start them in detached mode
    docker compose up --build -d
    ```

    -   `docker compose down`: This command stops and removes the existing containers, networks, and volumes defined in your `docker-compose.yml`.
    -   `docker compose up --build -d`:
        -   `--build`: This flag forces Docker Compose to rebuild the images before starting the containers. This is crucial for picking up any code changes (including `CLAUDE.md` updates, as it's part of the application context) or changes to the `Dockerfile`.
        -   `-d`: This runs the services in detached mode, meaning they will run in the background.

After completing these steps, your application on the Linode server should be running with the latest updates.



| Service | Purpose | Port |
|---------|---------|------|
| `redis` | Celery broker + result backend + cache | internal |
| `app` | FastAPI web server | 8000 (internal) |
| `celery_worker` | Background report generation | — |
| `nginx` | Reverse proxy + static files | 8281 |

The `app` and `celery_worker` containers use the same Docker image (`docker/app/Dockerfile`).
