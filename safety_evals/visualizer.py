"""
Visualization Generator for Safety Red-Team Evals.
"""

import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from typing import Dict, Any
from safety_evals.schema import DefenseVariant, SeverityLevel, AttackCategory


class Visualizer:
    """Generates comparison charts for red-teaming safety evaluations."""

    @staticmethod
    def generate_all_figures(
        suite_metrics: Dict[str, Any], output_dir: str = "reports/figures"
    ) -> Dict[str, str]:
        os.makedirs(output_dir, exist_ok=True)
        generated = {}

        # 1. Defense Efficacy Comparison
        def_path = os.path.join(output_dir, "defense_efficacy_comparison.png")
        Visualizer._plot_defense_efficacy(suite_metrics, def_path)
        generated["defense_efficacy_comparison"] = def_path

        # 2. Vulnerability by Category
        cat_path = os.path.join(output_dir, "vulnerability_by_category.png")
        Visualizer._plot_vulnerability_by_category(suite_metrics, cat_path)
        generated["vulnerability_by_category"] = cat_path

        # 3. Severity Breakdown
        sev_path = os.path.join(output_dir, "severity_breakdown.png")
        Visualizer._plot_severity_breakdown(suite_metrics, sev_path)
        generated["severity_breakdown"] = sev_path

        return generated

    @staticmethod
    def _plot_defense_efficacy(metrics: Dict[str, Any], output_path: str):
        fig, ax = plt.subplots(figsize=(9, 5))
        variants = ["Def_v0_Raw", "Def_v1_PromptGuard", "Def_v2_DualFilter"]
        labels = ["Def v0\n(Raw Model)", "Def v1\n(Prompt Guard)", "Def v2\n(Dual Filter)"]

        def_success = [metrics.get(v, {}).get("defense_success_rate", 0.0) * 100 for v in variants]
        attack_success = [metrics.get(v, {}).get("attack_success_rate", 0.0) * 100 for v in variants]

        x = np.arange(len(labels))
        width = 0.35

        rects1 = ax.bar(x - width/2, def_success, width, label="Defense Success Rate (%)", color="#5cb85c")
        rects2 = ax.bar(x + width/2, attack_success, width, label="Attack Success Rate (ASR %)", color="#d9534f")

        ax.set_ylabel("Percentage (%)", fontsize=11, fontweight="bold")
        ax.set_title("Safety Defense Efficacy Comparison (v0 Raw vs v1 Guard vs v2 Dual)", fontsize=12, fontweight="bold", pad=15)
        ax.set_xticks(x)
        ax.set_xticklabels(labels)
        ax.set_ylim(0, 115)
        ax.legend(loc="upper left")
        ax.grid(axis="y", linestyle=":", alpha=0.6)

        for rects in [rects1, rects2]:
            for r in rects:
                h = r.get_height()
                ax.text(r.get_x() + r.get_width()/2., h + 1.5, f"{h:.1f}%", ha="center", va="bottom", fontsize=9, fontweight="bold")

        plt.tight_layout()
        plt.savefig(output_path, dpi=200)
        plt.close()

    @staticmethod
    def _plot_vulnerability_by_category(metrics: Dict[str, Any], output_path: str):
        fig, ax = plt.subplots(figsize=(11, 5))
        categories = [c.value for c in AttackCategory]
        cat_labels = [c.replace("_", "\n") for c in categories]

        variants = ["Def_v0_Raw", "Def_v1_PromptGuard", "Def_v2_DualFilter"]
        colors = ["#d9534f", "#f0ad4e", "#5cb85c"]
        v_labels = ["v0 Raw", "v1 Guard", "v2 Dual"]

        x = np.arange(len(categories))
        width = 0.25

        for i, (v, label, color) in enumerate(zip(variants, v_labels, colors)):
            asrs = [
                metrics.get(v, {}).get("category_metrics", {}).get(cat, {}).get("attack_success_rate", 0.0) * 100
                for cat in categories
            ]
            rects = ax.bar(x + (i - 1) * width, asrs, width, label=label, color=color)
            for r in rects:
                h = r.get_height()
                ax.text(r.get_x() + r.get_width()/2., h + 1.0, f"{h:.0f}%", ha="center", va="bottom", fontsize=7, fontweight="bold")

        ax.set_ylabel("Attack Success Rate (ASR %)", fontsize=11, fontweight="bold")
        ax.set_title("Vulnerability / ASR Breakdown per Attack Category", fontsize=12, fontweight="bold", pad=15)
        ax.set_xticks(x)
        ax.set_xticklabels(cat_labels)
        ax.set_ylim(0, 115)
        ax.legend(loc="upper right")
        ax.grid(axis="y", linestyle=":", alpha=0.6)

        plt.tight_layout()
        plt.savefig(output_path, dpi=200)
        plt.close()

    @staticmethod
    def _plot_severity_breakdown(metrics: Dict[str, Any], output_path: str):
        fig, ax = plt.subplots(figsize=(9, 5))
        variants = ["Def_v0_Raw", "Def_v1_PromptGuard", "Def_v2_DualFilter"]
        labels = ["Def v0 (Raw)", "Def v1 (Guard)", "Def v2 (Dual)"]

        sevs = [s.value for s in SeverityLevel]
        colors = {"Critical": "#d9534f", "High": "#f0ad4e", "Medium": "#5bc0de", "Low": "#2b5c8f", "Safe": "#5cb85c"}

        bottom = np.zeros(len(variants))

        for s in sevs:
            vals = [metrics.get(v, {}).get("severity_distribution", {}).get(s, 0) for v in variants]
            ax.bar(labels, vals, bottom=bottom, label=s, color=colors[s], width=0.4, edgecolor="#333333")
            bottom += np.array(vals)

        ax.set_ylabel("Number of Attack Cases", fontsize=11, fontweight="bold")
        ax.set_title("Severity Distribution per Defense Variant", fontsize=12, fontweight="bold", pad=15)
        ax.legend(loc="upper right")
        ax.grid(axis="y", linestyle=":", alpha=0.6)

        plt.tight_layout()
        plt.savefig(output_path, dpi=200)
        plt.close()
