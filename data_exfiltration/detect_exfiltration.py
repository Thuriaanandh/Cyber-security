#!/usr/bin/env python3
"""
detect_exfiltration.py -- Main entry-point for the Forensic Exfiltration Detector.

Usage
-----
Analyse a real PCAP file:
    python detect_exfiltration.py --pcap traffic.pcap --output results/

Run on synthetic data (no PCAP required):
    python detect_exfiltration.py --synthetic --output results/

Train models from a CSV dataset:
    python detect_exfiltration.py --train data/sample_dataset.csv

Generate a synthetic training dataset:
    python detect_exfiltration.py --generate-dataset data/my_dataset.csv
"""

from __future__ import annotations
import argparse
import os
import sys

import pandas as pd

from utils import setup_logger, ensure_dir

logger = setup_logger(__name__, log_file="output/detect.log")


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

def run_pipeline(pcap_path: str, output_dir: str, skip_ml: bool = False) -> pd.DataFrame:
    """
    Execute the full detection pipeline on a PCAP file.

    Stages
    ------
    1  Parse PCAP -> packets
    2  Build flows
    3  Extract features -> DataFrame
    4  Heuristic detection
    5  ML detection (unless --skip-ml)
    6  Write forensic artifacts
    7  Generate visualisation charts

    Args:
        pcap_path:  Path to .pcap file.
        output_dir: Directory for all output files.
        skip_ml:    Skip ML models (useful when models are not yet trained).

    Returns:
        Results DataFrame.
    """
    ensure_dir(output_dir)

    # -- 1. Parse PCAP -------------------------------------------------------
    from pcap_parser import load_packets
    logger.info("Stage 1: Parsing PCAP -- %s", pcap_path)
    packets = load_packets(pcap_path)
    if not packets:
        logger.error("No packets parsed from %s", pcap_path)
        sys.exit(1)

    # -- 2. Build flows -------------------------------------------------------
    from flow_builder import build_flows, flows_to_list
    logger.info("Stage 2: Building flows from %d packets", len(packets))
    flow_dict = build_flows(packets)
    flows = flows_to_list(flow_dict)

    # -- 3. Feature extraction ------------------------------------------------
    from feature_extractor import flows_to_dataframe
    logger.info("Stage 3: Extracting features from %d flows", len(flows))
    df = flows_to_dataframe(flows, label="unknown")

    # -- 4. Heuristic detection -----------------------------------------------
    from heuristic_detector import apply_heuristics
    logger.info("Stage 4: Applying heuristic rules")
    df = apply_heuristics(df)

    # -- 5. ML detection ------------------------------------------------------
    if not skip_ml:
        from ml_detector import predict
        logger.info("Stage 5: Running ML detection")
        df = predict(df)
    else:
        logger.info("Stage 5: ML detection skipped (--skip-ml flag)")

    # -- 6. Forensic artifacts ------------------------------------------------
    from forensic_writer import write_all_artifacts
    logger.info("Stage 6: Writing forensic artifacts to %s", output_dir)
    artifacts = write_all_artifacts(df, output_dir)
    for name, path in artifacts.items():
        if path:
            logger.info("  %-20s -> %s", name, path)

    # -- 7. Visualisations ----------------------------------------------------
    from visualization import generate_all_charts
    logger.info("Stage 7: Generating visualisation charts")
    charts = generate_all_charts(df, output_dir)

    _print_summary(df)
    return df


def run_synthetic_pipeline(output_dir: str, skip_ml: bool = False) -> pd.DataFrame:
    """
    Run detection on synthetic data (no PCAP needed).

    Generates ~200 flows (mix of benign + attack), trains models on a larger
    synthetic corpus, then runs the full detection pipeline.
    """
    ensure_dir(output_dir)

    # -- Generate small synthetic corpus for inference -----------------------
    from attack_simulator import generate_dataset
    logger.info("Generating synthetic inference dataset ...")
    df_infer = generate_dataset(
        n_benign=150, n_dns=30, n_https=30, n_covert=30, n_slow=20
    )

    # -- Train (or load) models ----------------------------------------------
    from ml_detector import load_models, train_models
    rf, iso, scaler = load_models()
    if rf is None:
        logger.info("No saved models found -- training on synthetic data ...")
        df_train = generate_dataset(
            n_benign=1000, n_dns=200, n_https=200, n_covert=200, n_slow=150
        )
        rf, iso, scaler = train_models(df_train)

    # -- Heuristics ----------------------------------------------------------
    from heuristic_detector import apply_heuristics
    df_infer = apply_heuristics(df_infer)

    # -- ML detection --------------------------------------------------------
    if not skip_ml:
        from ml_detector import predict
        df_infer = predict(df_infer, rf=rf, iso=iso, scaler=scaler)

    # -- Artifacts & charts --------------------------------------------------
    from forensic_writer import write_all_artifacts
    write_all_artifacts(df_infer, output_dir)

    from visualization import generate_all_charts
    generate_all_charts(df_infer, output_dir, rf_model=rf)

    _print_summary(df_infer)
    return df_infer


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _print_summary(df: pd.DataFrame) -> None:
    """Print a terminal summary of detection results."""
    label_col = "ml_label" if "ml_label" in df.columns else "heuristic_label"
    print("\n" + "=" * 60)
    print("  DETECTION SUMMARY")
    print("=" * 60)
    print(f"  Total flows analysed : {len(df)}")
    if label_col in df.columns:
        counts = df[label_col].value_counts()
        for lbl, cnt in counts.items():
            print(f"  {lbl:<28} : {cnt}")
    if "entropy" in df.columns:
        print(f"  Mean entropy         : {df['entropy'].mean():.3f} bits/byte")
        print(f"  Max entropy          : {df['entropy'].max():.3f} bits/byte")
    print("=" * 60 + "\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="detect_exfiltration.py",
        description="Forensic Detection of Encrypted Data Exfiltration Attacks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    inp = p.add_mutually_exclusive_group(required=False)
    inp.add_argument("--pcap", metavar="FILE",
                     help="Path to PCAP/PCAPNG file to analyse.")
    inp.add_argument("--synthetic", action="store_true",
                     help="Run on synthetically generated traffic (no PCAP needed).")
    inp.add_argument("--train", metavar="CSV",
                     help="Train ML models from a labelled CSV file and save them.")
    inp.add_argument("--generate-dataset", metavar="CSV",
                     help="Generate synthetic labelled dataset and save as CSV.")

    p.add_argument("--output", "-o", metavar="DIR", default="output",
                   help="Output directory for all artifacts (default: output/).")
    p.add_argument("--skip-ml", action="store_true",
                   help="Skip ML detection (use heuristics only).")
    p.add_argument("--verbose", "-v", action="store_true",
                   help="Enable verbose logging.")

    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.verbose:
        import logging
        logging.getLogger().setLevel(logging.DEBUG)

    # -- Mode: generate synthetic dataset ------------------------------------
    if args.generate_dataset:
        from attack_simulator import generate_dataset
        ensure_dir(os.path.dirname(args.generate_dataset) or ".")
        df = generate_dataset(save_path=args.generate_dataset)
        print(f"Dataset saved: {args.generate_dataset}  ({len(df)} rows)")
        return

    # -- Mode: train models --------------------------------------------------
    if args.train:
        from ml_detector import train_models
        logger.info("Training models from %s ...", args.train)
        df = pd.read_csv(args.train)
        train_models(df)
        print("Models trained and saved to models/")
        return

    # -- Mode: PCAP analysis -------------------------------------------------
    if args.pcap:
        if not os.path.isfile(args.pcap):
            print(f"ERROR: PCAP file not found: {args.pcap}", file=sys.stderr)
            sys.exit(1)
        run_pipeline(args.pcap, args.output, skip_ml=args.skip_ml)
        return

    # -- Mode: synthetic demo ------------------------------------------------
    if args.synthetic or not any([args.pcap, args.train, args.generate_dataset]):
        logger.info("Running synthetic demo pipeline ...")
        run_synthetic_pipeline(args.output, skip_ml=args.skip_ml)
        return

    parser.print_help()


if __name__ == "__main__":
    main()
