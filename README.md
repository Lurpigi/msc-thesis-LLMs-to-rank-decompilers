# LLMs to Rank Decompilers

This repository contains the code and artifacts for a Master's thesis on evaluating decompiled code with local LLMs.
The core question is: can LLM-based metrics and judgments approximate human preference for more readable decompilation outputs?

## Why This Design

- Local inference first: privacy, reproducibility, and cost control.
- Real-world data: subset of OSS-Fuzz functions, not synthetic snippets.
- PR-level evaluation: compare Ghidra `base` vs specific pull request branches.
- Dual evaluation: quantitative scoring (perplexity/loss) + qualitative LLM-as-a-judge.
- Structural abstraction: AST anonymization to reduce lexical noise and naming bias.

## Project Structure (minimal)

- `Dataset_maker/`: builds the benchmark dataset from selected OSS-Fuzz projects.
- `llm_server/`: Flask API for model generation, scoring, and token-level loss.
- `ghidra_bench/`: evaluates Ghidra PRs against a fixed base build.
- `dogbolt_bench/`: cross-decompiler comparison (Ghidra, Binary Ninja, Hex-Rays, etc.).
- `reports_viewer/`: static report viewer.
- `Latex/`: thesis manuscript, methodology, and full result discussion.

## Study Results (short)

- Average perplexity was not a reliable proxy for human-likeness in this setting.
- Decompiled code often scored lower perplexity than source due to repetitive/verbose patterns.
- LLM-as-a-judge produced useful signal on specific transformations:
  - PR #8587 (indexing pattern recognition): strong preference for PR outputs.
  - PR #8628 (negative constant subtraction normalization): PR often preferred.
- Aggregate judgments showed frequent ties and positional effects; bias handling remained necessary.
- In the thesis human-check subset, DeepSeek-R1 reached about 74% alignment with developer choices.

## Takeaways

- Perplexity alone is insufficient for decompiler quality ranking.
- Structural representations (AST) help isolate meaningful differences.
- Total loss on anonymized AST is a promising direction, but not yet definitive.
- LLM judges are useful but still sensitive to bias and hallucinated justifications.

## Limitations

- Limited model diversity (mostly Qwen-family variants in the final setup).
- Dataset and human validation sample are constrained.
- Some PR comparisons are affected by branch/version drift.

## Reproducibility

- Main orchestration: `docker compose` + `just` targets.
- Main outputs: `ghidra_bench/outputs/reports/` and `dogbolt_bench/outputs/`.
- Full methodological details: `Latex/content/method.tex` and `Latex/content/results.tex`.
