UI and report deletion regression checks:

```sh
pip install -r requirements-dev.txt
python -m playwright install --with-deps chromium
python -m pytest tests -q
```

Browser checks start a loopback-only fixture server with synthetic account data.
Account search and deletion are simulated; no production audit or deletion requests
are made. Screenshots are saved under /tmp/audit-ui-*.png.

Deletion tests use fake Redis/Celery services and temporary report files.
