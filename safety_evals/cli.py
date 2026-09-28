"""
CLI Interface for LLM Safety Red-Team Evals.
"""

import argparse
import sys
from safety_evals.schema import SafetyDataset, DefenseVariant
from safety_evals.experiment_runner import ExperimentRunner
from safety_evals.metrics import MetricsCalculator
from safety_evals.visualizer import Visualizer
from safety_evals.report_generator import ReportGenerator


def main():
    parser = argparse.ArgumentParser(description="LLM Safety Red-Team Evals CLI")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    run_parser = subparsers.add_parser("run", help="Run safety red-teaming evaluation suite")
    run_parser.add_argument("--dataset", required=True, help="Path to JSONL attack dataset")
    run_parser.add_argument("--output-dir", default="results", help="Directory to save JSON/CSV outputs")
    run_parser.add_argument("--report-path", default="reports/safety_redteam_report.md", help="Path to save Markdown report")
    run_parser.add_argument("--figures-dir", default="reports/figures", help="Directory to save figure plots")

    args = parser.parse_args()

    if args.command == "run":
        print(f"Loading attack dataset from: {args.dataset}")
        dataset = SafetyDataset.from_jsonl(args.dataset)
        print(f"Loaded {len(dataset.cases)} attack test cases.")

        print("Evaluating defense configurations (v0 Raw, v1 Guard, v2 Dual Filter)...")
        all_evaluations = {
            DefenseVariant.DEF_V0_RAW: [],
            DefenseVariant.DEF_V1_PROMPT_GUARD: [],
            DefenseVariant.DEF_V2_DUAL_FILTER: [],
        }

        for case in dataset.cases:
            res_dict = ExperimentRunner.evaluate_attack_case(case)
            for def_v, res in res_dict.items():
                all_evaluations[def_v].append(res)

        metrics = MetricsCalculator.calculate_suite_metrics(all_evaluations)
        print("\nDefense Performance Summary:")
        for def_v, m in metrics.items():
            print(f"  {def_v}: Defense Success Rate={m['defense_success_rate']*100:.1f}%, Critical Breaches={m['critical_breaches']}")

        print(f"\nExporting results to: {args.output_dir}")
        ReportGenerator.export_results(all_evaluations, args.output_dir)

        print(f"Generating visualizations in: {args.figures_dir}")
        Visualizer.generate_all_figures(metrics, args.figures_dir)

        print(f"Generating research report at: {args.report_path}")
        ReportGenerator.generate_markdown_report(metrics, args.report_path)

        print("\nSafety Red-Team Evaluation completed successfully!")
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
