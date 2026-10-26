# Self-Learning Demo

Demonstrates the self-hardening feedback loop: vault storage, similarity matching, feedback, and threat export.

## Setup

```bash
pip install -e .   # from the repository root
```

## Run

```bash
python examples/self_learning_demo/app.py
```

## How the Self-Learning Loop Works

1. **Detection**: Engine scans input with 36 detectors (33 on by default)
2. **Vault storage**: Detected attacks are embedded and stored in ChromaDB when `vault.auto_store_detections` is on (off by default; this demo turns it on)
3. **Similarity matching**: Future inputs are compared against stored embeddings (d021_vault_similarity)
4. **Feedback**: Users mark false positives/true positives via `engine.feedback()`
5. **Auto-tuning**: When `feedback.auto_tune` is on (off by default), after every `tune_interval` scans the auto-tuner adjusts per-detector thresholds based on accumulated feedback
6. **Threat export**: Locally-detected attacks can be exported as anonymized JSON for community sharing
7. **Threat import**: Other instances import feeds to strengthen their vaults without seeing raw attack text

Each blocked attack makes the system more resistant to paraphrased variants.
