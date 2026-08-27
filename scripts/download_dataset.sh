#!/usr/bin/env bash
# Download the REAL dataset Sentinel trains on: CSE-CIC-IDS2018,
# Thursday-01-03-2018 (the Infiltration attack day), CICFlowMeter processed flow
# CSV — 331k labelled flows, ~28% Infiltration, ~103 MB. Public, no credentials.
#
#   bash scripts/download_dataset.sh
#
# Then train:  python train.py   (reads config/train_config.yaml -> data/raw/...)
set -euo pipefail

DEST_DIR="$(cd "$(dirname "$0")/.." && pwd)/data/raw"
DEST="$DEST_DIR/cicids2018_thu01mar.csv"
URL="https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/Processed%20Traffic%20Data%20for%20ML%20Algorithms/Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv"

mkdir -p "$DEST_DIR"
if [ -f "$DEST" ]; then
  echo "Already present: $DEST"
  exit 0
fi
echo "Downloading CIC-IDS2018 Infiltration day (~103 MB) …"
curl -f --retry 3 -o "$DEST" "$URL"
echo "Saved -> $DEST"
echo "Rows: $(( $(wc -l < "$DEST") - 1 ))"
