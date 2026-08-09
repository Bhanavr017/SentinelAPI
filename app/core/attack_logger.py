import logging
from pathlib import Path


# ============================================================
# Paths
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent.parent

LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

ATTACK_LOG_FILE = LOG_DIR / "attacks.log"


# ============================================================
# Logger
# ============================================================

attack_logger = logging.getLogger("sentinelapi.attack")

attack_logger.setLevel(logging.WARNING)

# Prevent messages from propagating to the root logger
attack_logger.propagate = False


# ============================================================
# File Handler
# ============================================================

if not attack_logger.handlers:

    file_handler = logging.FileHandler(
        ATTACK_LOG_FILE,
        encoding="utf-8",
    )

    file_handler.setLevel(logging.WARNING)

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(message)s"
    )

    file_handler.setFormatter(formatter)

    attack_logger.addHandler(file_handler)


# ============================================================
# Attack Logging
# ============================================================

def log_attack(
    *,
    ip_address: str,
    method: str,
    path: str,
    score: int,
    reason: str,
    user_agent: str = "",
) -> None:

    attack_logger.warning(
        "ATTACK | "
        f"IP={ip_address} | "
        f"METHOD={method} | "
        f"PATH={path} | "
        f"SCORE={score} | "
        f"REASON={reason} | "
        f"USER_AGENT={user_agent}"
    )