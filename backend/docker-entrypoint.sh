#!/bin/sh
set -eu

python -m reversing_lab.database.migrate
exec uvicorn reversing_lab.api.app:app --host 0.0.0.0 --port 8000 --reload
