import argparse
import logging
import sys
from pathlib import Path

# Ensure repo root takes precedence over stdlib code module
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from code.detectors.document.scanner import DocumentAndImageScanner
from code.detectors.logs.scanner import TextLogScanner
from code.detectors.records.scanner import JsonRecordsScanner
from code.detectors.sql.checker import SqlSnapshotChecker
from code.evaluation.harness.validator import validate_output_file
from code.filesystem.reader import (
    read_deletion_requests,
    read_deletion_rules,
    read_evidence_files,
    read_system_activity,
    read_user_audit_log,
    read_user_identities,
)
from code.filesystem.writer import write_output_csv
from code.llm.vision_client import VisionClient
from code.pipeline.classifier.request_classifier import HybridRequestClassifier
from code.pipeline.identity.resolver import IdentityResolver
from code.pipeline.runner.orchestrator import PipelineOrchestrator

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("spectral.main")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Spectral - AI Deletion-Audit Agent (HackerRank Orchestrate)"
    )
    parser.add_argument(
        "--dataset-dir",
        type=Path,
        default=Path("dataset"),
        help="Path to dataset directory containing participant context and evidence.",
    )
    parser.add_argument(
        "--requests",
        type=Path,
        default=None,
        help="Path to deletion requests CSV. Defaults to <dataset-dir>/deletion_requests.csv.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("output.csv"),
        help="Destination path for final audit predictions CSV (default: output.csv at repo root).",
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        default=True,
        help="Validate generated output against the challenge contract after run (default: True).",
    )
    return parser.parse_args()


def run_pipeline(
    dataset_dir: Path,
    requests_path: Path,
    output_path: Path,
    validate: bool = True,
) -> int:
    logger.info("Initializing Spectral deletion-audit pipeline...")
    logger.info("Dataset directory: %s", dataset_dir.resolve())
    logger.info("Requests file: %s", requests_path.resolve())
    logger.info("Output file: %s", output_path.resolve())

    # 1. Load context inputs
    requests = read_deletion_requests(requests_path)
    rules = read_deletion_rules(dataset_dir / "deletion_rules.csv")
    evidence_files = read_evidence_files(dataset_dir / "evidence_files.csv")
    system_activity = read_system_activity(dataset_dir / "system_activity.csv")
    identities = read_user_identities(dataset_dir / "user_identities.csv")
    audit_log = read_user_audit_log(dataset_dir / "user_audit_log.csv")

    logger.info("Loaded %d deletion requests to audit.", len(requests))
    logger.info(
        "Loaded %d deletion rules, %d evidence files.", len(rules), len(evidence_files)
    )

    # 2. Build identity resolver, Vision LLM client, and hybrid classifier
    resolver = IdentityResolver(
        identities=identities,
        audit_log=audit_log,
        dataset_dir=dataset_dir,
    )
    vision_client = VisionClient(
        cache_file=dataset_dir / "evidence" / ".vision_cache.json"
    )
    classifier = HybridRequestClassifier(
        llm_fallback=lambda text: vision_client.classify_deletion_intent(text).get(
            "is_deletion", True
        )
    )

    # 3. Instantiate pluggable detectors
    doc_scanner = DocumentAndImageScanner(
        dataset_dir=dataset_dir, vision_client=vision_client
    )
    detectors = [
        SqlSnapshotChecker(dataset_dir=dataset_dir),
        JsonRecordsScanner(dataset_dir=dataset_dir),
        TextLogScanner(dataset_dir=dataset_dir),
        doc_scanner,
    ]

    # 4. Instantiate pipeline orchestrator
    orchestrator = PipelineOrchestrator(
        detectors=detectors,
        classifier=classifier,
        identity_resolver=resolver.resolve_for_request,
        rules=rules,
        evidence_files=evidence_files,
        system_activity=system_activity,
    )

    # 5. Audit all requests
    logger.info("Auditing %d requests...", len(requests))
    results = orchestrator.audit_all(requests)
    logger.info("Audit completed. Writing output to %s...", output_path)

    # Log Vision LLM metrics
    llm_metrics = vision_client.get_metrics()
    logger.info("Vision LLM Metrics: %s", llm_metrics)

    # 6. Write formatted CSV
    written_path = write_output_csv(results, output_path)
    logger.info("Successfully wrote %s.", written_path)

    # 7. Post-run validation
    if validate:
        logger.info("Validating output against challenge contract...")
        report = validate_output_file(written_path, expected_count=len(requests))
        if not report.is_valid:
            logger.error("Validation failed with %d errors:", len(report.errors))
            for err in report.errors[:10]:
                logger.error("  %s", err)
            return 1
        logger.info(
            "Validation passed: output strictly complies with AGENTS.md contract!"
        )

    return 0


def main() -> None:
    args = parse_args()
    req_path = args.requests or (args.dataset_dir / "deletion_requests.csv")
    exit_code = run_pipeline(
        dataset_dir=args.dataset_dir,
        requests_path=req_path,
        output_path=args.output,
        validate=args.validate,
    )
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
