# CYPHEX Fine-Tuning Guide — qwen2.5-coder:7b for Cybersecurity Patching

> **Status: optional and experimental.** CYPHEX runs fully on stock Ollama
> models; nothing in the scan pipeline requires a fine-tuned model. This is a
> path to a *better* patcher, not a prerequisite. See
> [`../README.md`](../README.md) to run CYPHEX.

## Overview

Fine-tune `qwen2.5-coder:7b` to become a cybersecurity specialist using QLoRA.
After fine-tuning, the model generates better vulnerability patches and attack payloads.

---

## Step 1: Generate Training Data (DONE ✅)

```bash
cd /path/to/Cyphex_CLI            # the repo root
python finetune/training_data.py
# Output: cyphex_training_data.jsonl (12 examples covering 9 vulnerability categories)
```

To add more examples, edit `finetune/training_data.py` and add to the `TRAINING_DATA` list.
Each example has: `instruction`, `input` (vulnerable code), `output` (patched code).

---

## Step 2: Install Fine-Tuning Dependencies

```powershell
# Install Unsloth (fastest QLoRA trainer, 2x faster than standard HF)
pip install "unsloth[colab-new]" --quiet
pip install --no-deps "trl<0.9.0" peft accelerate bitsandbytes
```

> ⚠️ **VRAM Check:** Your RTX 3050 has 6GB VRAM.
> QLoRA loads the model in 4-bit (~2.5GB) + LoRA adapters (~200MB) = ~3GB total.
> You have enough headroom. Close Chrome/VS Code during training.

---

## Step 3: Run Fine-Tuning

```powershell
cd /path/to/Cyphex_CLI            # the repo root
python finetune/train.py
```

**Expected time:** 30-60 minutes on RTX 3050 (12 examples × 3 epochs = 36 training steps)

**Expected output:**
```
Loading base model (4-bit quantized)...
Training with QLoRA (rank=16, alpha=32)...
Step 10/36: loss=1.234
Step 20/36: loss=0.567
Step 36/36: loss=0.123
Saving LoRA adapter to finetune/cyphex-adapter/
Merging adapter into base model...
Saving merged model to finetune/cyphex-merged/
Converting to GGUF format...
Done! Import to Ollama with: ollama create cyphex-patch -f finetune/Modelfile
```

---

## Step 4: Import to Ollama

```powershell
# Create Ollama model from fine-tuned GGUF
ollama create cyphex-patch -f finetune/Modelfile
```

Then update `config.py`:
```python
OLLAMA_MODEL: str = "cyphex-patch"  # Use your fine-tuned model
```

---

## Step 5: Test the Fine-Tuned Model

```powershell
ollama run cyphex-patch "Fix the SQL injection vulnerability in this code:
@app.route('/search')
def search():
    q = request.args.get('q')
    result = db.execute(f\"SELECT * FROM products WHERE name LIKE '%{q}%'\")
    return jsonify(result)"
```

The fine-tuned model should generate a parameterized query fix with detailed comments.

---

## Important Notes

1. **12 examples is a starting point.** For production quality, aim for 200-500 examples.
2. **Data quality > quantity.** Each example should have clear before/after code + explanation.
3. **The base model already works.** Fine-tuning is an optimization, not a requirement.
4. **You can always add more data later** and re-train (incremental improvement).
