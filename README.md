# js_pipeline — JS malicious/benign feature extraction

A static-analysis feature-extraction pipeline for training an ML classifier
to distinguish malicious from benign JavaScript. No sample is ever executed
— all features come from text/regex analysis and AST parsing
([tree-sitter](https://tree-sitter.github.io/tree-sitter/)).

## Layout

```
src/jsmal/
  lexical_features.py   # regex/text features (entropy, suspicious APIs, encodings, ...)
  ast_features.py        # tree-sitter AST structural features
  extractor.py            # combines both into one feature vector per file
  dataset.py               # walks a labeled dataset -> pandas DataFrame
scripts/
  build_dataset.py   # CLI: dataset -> feature table (csv/parquet)
  train_model.py         # CLI: feature table -> trained RandomForest + report
  predict.py                # CLI: classify new .js file(s) with a trained model
data/raw/
  benign/       # put benign .js samples here (any nesting)
  malicious/    # put malicious .js samples here (any nesting)
data/processed/  # generated feature tables land here
models/                # generated model artifacts land here
tests/                    # pytest suite + safe synthetic fixtures
```

## Setup

```powershell
py -3.12 -m venv .venv
./.venv/Scripts/python.exe -m pip install -r requirements.txt
```

(Use a 64-bit Python — pandas/scikit-learn don't publish win32 wheels and
will try to build from source.)

## Usage

1. Populate `data/raw/benign/` and `data/raw/malicious/` with labeled `.js`
   files (see `data/raw/README.md` for the manifest-CSV alternative).

2. Extract features:

   ```powershell
   ./.venv/Scripts/python.exe scripts/build_dataset.py --data-root data/raw --output data/processed/features.csv -v
   ```

3. Train a baseline model:

   ```powershell
   ./.venv/Scripts/python.exe scripts/train_model.py --features data/processed/features.csv --model-out models/rf_model.joblib
   ```

   Prints a classification report, ROC-AUC, and top feature importances.

4. Classify new files:

   ```powershell
   ./.venv/Scripts/python.exe scripts/predict.py --model models/rf_model.joblib path/to/file.js
   ```

Run tests with:

```powershell
./.venv/Scripts/python.exe -m pytest tests/ -v
```

## Feature set (~65 features per file)

**Lexical** (always computed, even if parsing fails):
- Size/line stats, single-line ("minified") ratio
- Shannon entropy of whole file and of string literals (avg/max)
- Comment ratio/count
- String literal count/length stats
- Hex (`\x..`) / unicode (`\u....`) escape counts, base64-blob-like run count
- URL / IP literal counts
- Identifier stats: count, avg length, short-identifier ratio, uniqueness ratio
- Suspicious API/keyword group counts: `dynamic_exec` (eval/Function),
  `encoding` (atob/btoa/fromCharCode/...), `dom_injection`, `network`
  (XHR/fetch/ActiveXObject/WScript.Shell/...), `process_fs` (child_process/
  fs/exec), `obfuscation_markers` (packer signature, `with`, `__proto__`,
  `arguments.callee`, ...), `crypto_mining`, `shell_download`
  (powershell/certutil/...)
- Punctuation density

**AST** (via tree-sitter, best-effort — `parse_failed`/`parse_has_error`
flags let the model learn from broken/adversarial syntax too):
- Total node count, max tree depth
- Per-node-type counts (functions, classes, loops, try/catch, calls,
  member/subscript/assignment expressions, strings, regex, ...)
- `eval`/`Function(` call count, IIFE count
- Function-expression-vs-declaration ratio (obfuscators favor expressions)
- Cyclomatic-complexity approximation (branch node count + 1)

## Extending

- Add a new lexical signal: extend `KEYWORD_GROUPS` or add a new regex +
  feature key in `lexical_features.extract_lexical_features`.
- Add a new structural signal: extend `_STRUCTURAL_NODE_TYPES` or the
  traversal loop in `ast_features.extract_ast_features`.
- Swap the classifier: `scripts/train_model.py` only depends on the feature
  table having a `label` column plus numeric feature columns — drop in
  XGBoost/LightGBM/etc. there.

## Working with real malware samples

- This pipeline never executes sample code — extraction is 100% static.
- Only use samples you're authorized to hold (your own incident corpus, or
  an established public research dataset released for this purpose).
- Store raw samples with the same care as any malware corpus (isolated
  storage/VM, no auto-synced network shares, narrowly-scoped AV exclusions).
- `data/raw/**/*.js` is gitignored by default so samples aren't accidentally
  committed.
