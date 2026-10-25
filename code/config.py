from pathlib import Path

# Repository root and primary directories
REPO_ROOT = Path(__file__).resolve().parent.parent
DATASET_DIR = REPO_ROOT / "dataset"
EVIDENCE_DIR = DATASET_DIR / "evidence"

# Dataset file paths
DELETION_REQUESTS_PATH = DATASET_DIR / "deletion_requests.csv"
SAMPLE_DELETION_REQUESTS_PATH = DATASET_DIR / "sample_deletion_requests.csv"
SAMPLE_OUTPUT_PATH = DATASET_DIR / "sample_output.csv"
USER_IDENTITIES_PATH = DATASET_DIR / "user_identities.csv"
USER_AUDIT_LOG_PATH = DATASET_DIR / "user_audit_log.csv"
SYSTEM_ACTIVITY_PATH = DATASET_DIR / "system_activity.csv"
DELETION_RULES_PATH = DATASET_DIR / "deletion_rules.csv"
EVIDENCE_FILES_PATH = DATASET_DIR / "evidence_files.csv"
OUTPUT_PATH = REPO_ROOT / "output.csv"
