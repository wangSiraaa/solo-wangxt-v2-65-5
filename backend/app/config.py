"""Configuration.

PostgreSQL is the production store (docker-compose starts postgres:16).
DATABASE_URL=postgresql+psycopg://... overrides; otherwise SQLite under
./data is used so the whole workbench is runnable/tested without a DB.
"""
import os
from pathlib import Path

DATA_DIR = Path(os.environ.get("RLAB_DATA", Path(__file__).resolve().parents[1] / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    f"sqlite:///{DATA_DIR / 'rlab.db'}",
)

FRR_HOST_A = os.environ.get("FRR_HOST_A", "127.0.0.1")
FRR_HOST_B = os.environ.get("FRR_HOST_B", "127.0.0.1")
FRR_SSH_PORT_A = int(os.environ.get("FRR_SSH_PORT_A", "2222"))
FRR_SSH_PORT_B = int(os.environ.get("FRR_SSH_PORT_B", "2223"))
FRR_SSH_USER = os.environ.get("FRR_SSH_USER", "root")
FRR_SSH_PASSWORD = os.environ.get("FRR_SSH_PASSWORD", "frrouting")

# "local" transport: a native vtysh on the API host (e.g. FRR extracted
# from debs into a prefix, run unprivileged with a unix vty socket).
FRR_LOCAL_VTYSH = os.environ.get("FRR_LOCAL_VTYSH", "vtysh")
FRR_LOCAL_VTY_SOCKET = os.environ.get("FRR_LOCAL_VTY_SOCKET", "/var/run/frr")
FRR_LOCAL_CONFIG_DIR = os.environ.get("FRR_LOCAL_CONFIG_DIR", "/etc/frr")
FRR_LOCAL_DAEMON = os.environ.get("FRR_LOCAL_DAEMON", "bgpd")
# optional environment to inject (LD_LIBRARY_PATH/LD_PRELOAD/NSS_WRAPPER_*)
FRR_LOCAL_ENV = os.environ.get("FRR_LOCAL_ENV", "")

CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "http://localhost:5173").split(",")
