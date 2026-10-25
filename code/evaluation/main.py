import argparse
import sys
from code.config import OUTPUT_PATH, SAMPLE_OUTPUT_PATH
from code.evaluation.harness.evaluator import evaluate_predictions
from code.evaluation.harness.validator import validate_output_file
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Spectral Evaluation and Output Validation"
    )
    parser.add_argument(
        "--predicted",
        type=Path,
        default=OUTPUT_PATH,
        help="Path to predicted output.csv",
    )
    parser.add_argument(
        "--golden",
        type=Path,
        default=SAMPLE_OUTPUT_PATH,
        help="Path to ground truth golden output.csv",
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Only validate contract without computing evaluation metrics",
    )
    parser.add_argument(
        "--expected-count",
        type=int,
        default=None,
        help="Expected number of cases (e.g. 32 for sample, 518 for evaluation)",
    )
    parser.add_argument(
        "--report-out",
        type=Path,
        default=None,
        help="Path to write evaluation markdown report",
    )

    args = parser.parse_args()

    print(f"Validating contract for {args.predicted}...")
    val_report = validate_output_file(
        args.predicted, expected_count=args.expected_count
    )
    if not val_report.is_valid:
        print("Contract validation FAILED:")
        for err in val_report.errors[:15]:
            print(f"  - {err}")
        if len(val_report.errors) > 15:
            print(f"  ... and {len(val_report.errors) - 15} more errors.")
        sys.exit(1)

    print(f"Contract validation PASSED ({val_report.row_count} rows).")

    if args.validate_only:
        return

    if not args.golden.exists():
        print(f"Golden file not found at {args.golden}, skipping metric evaluation.")
        return

    print(f"Evaluating {args.predicted} against golden {args.golden}...")
    eval_report = evaluate_predictions(args.predicted, args.golden)
    md_content = eval_report.to_markdown()
    print("\n" + md_content)

    if args.report_out:
        args.report_out.parent.mkdir(parents=True, exist_ok=True)
        args.report_out.write_text(md_content, encoding="utf-8")
        print(f"Evaluation report written to {args.report_out}")


if __name__ == "__main__":
    main()
