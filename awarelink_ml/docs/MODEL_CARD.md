# AwareLink local models

These are trained research baselines, created on **1 October 2026**: URL **1.2.0**, SMS and news **1.0.0**. They run locally without LLMs, cloud inference, third-party runtime ML libraries, or per-prediction model loading. Scores describe similarity to labeled training examples. They do not establish safety or truth.

## Intended use and boundaries

| Model | Predicts | Does not establish |
| --- | --- | --- |
| URL | Historical phishing-like base-domain spelling and structure | Whether a live site is safe, compromised, or serving malicious content |
| Scam text | Similarity to historical English SMS spam | Whether a modern message is a scam |
| News | Wording associated with lower-veracity labels in LIAR | Whether a statement is true; political bias; reliability of a news source |

The news model **always returns `review`**, regardless of its probability. Its text-only test performance is weak and does not support automated truth judgments. Do not use any model to make decisions about people. The news artifact is restricted to research use by its dataset terms.

## Architecture and performance

All three models are L2 logistic regressions with 32,768 deterministic hashed feature slots. URLs use base-domain character 3-grams and 4-grams plus ten numeric domain structure features. Text uses words and bigrams, with URLs, email addresses and numbers normalized. Log term frequencies are L2 normalized. CRC32 gives stable feature identities across machines; collisions are possible, so word-level explanations are approximate associations.

URL features deliberately exclude the scheme, subdomain, path and query. Source collection artifacts made ordinary deep paths and hosts without `www` appear malicious. The final classifier normalizes to a coarse base domain, avoiding those artifacts without allowlisting familiar sites. It uses the final two labels, or three for common country-code second-level categories, and preserves full IP addresses. This is a lightweight approximation rather than a runtime Public Suffix List. Private hosting providers collapse to one base domain; malicious pages and ordinary pages on the same provider cannot be distinguished by this model. The application reports separate observed structural or credential-request policy signals; these do not change the model probability.

Fitting uses scikit-learn; JSON artifacts contain only coefficients, an intercept, metadata, and evaluation results. Serving uses the shared extractor, Python standard library, and immutable models loaded once at startup. Training and inference use exactly the same feature code. No `pickle` is loaded.

Artifacts total approximately **1.22 MB** on disk. Model-only short-input p95 measurements are recorded in `training/evaluation.json`; a typical prediction takes substantially less than 1 ms on the development machine. These are illustrative microbenchmarks, not end-to-end throughput or latency guarantees. Input limits are 2,048 URL characters and 12,000 text characters. Oversized inputs fail explicitly instead of silently truncating at inference.

## Evaluation

| Model | Test rows | Accuracy at 0.5 | Positive precision | Positive recall | F1 | ROC-AUC | Majority accuracy |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| URL | 44,797 | 80.69% | 88.14% | 59.45% | 71.01% | 0.8731 | 60.22% |
| SMS spam | 765 | 98.56% | 97.56% | 89.89% | 93.57% | 0.9935 | 88.37% |
| LIAR language | 1,262 | 63.23% | 60.33% | 46.10% | 52.26% | 0.6772 | 56.34% |

Positive means phishing, spam, or LIAR's lower-veracity label group, respectively. The news classification metrics are research measurements; production output is always review. Test data was held out until model selection finished. The seed is `20261001`. `C=1` was fixed for URLs; SMS and news selected from `0.25, 1, 4` using validation ROC-AUC, choosing `4` and `1` respectively. Weights remain fitted only on the training partition.

URL uses conservative display thresholds: probability at least `0.95` is high risk; at most `0.05` is low risk; the middle requires review. These thresholds were chosen for conservative triage after independent benign-domain sanity checks, without optimizing test labels. On the held-out split, 4,917 predictions (10.98% of all examples) are high risk with **99.78% positive precision**; this covers only **27.53% of actual phishing**. Low-score predictions contain **180 phishing examples among 4,159 predictions (4.33%)**. **79.74%** of URL examples require review. At a binary 0.5 cutoff, 7,226 of 17,821 phishing examples are missed. These limits matter more than an aggregate accuracy number.

SMS uses preset `0.2`/`0.8` thresholds. High-score precision is 98.51% on 67 of 765 examples (8.76% coverage); 66 of 89 spam examples are high risk (74.16% spam recall at the high threshold). Five of 669 low-score predictions are spam (0.75%). Scores have not been prospectively calibrated for deployment populations and must not be interpreted as guaranteed real-world risk percentages. No supported English word features produces review.

The URL result is **dataset-specific**, not a claim of live-world accuracy. Domain-separated splitting reduces same-domain leakage, but source artifacts and a single historical collection still limit generalization. It cannot identify path-specific phishing, a compromised trusted website, or malicious user pages on a legitimate hosting provider from the base domain alone. Domain shift and adversarial changes require evaluation on new local data and a time-separated holdout before deployment.

The evaluation also preserves hand-written illustrative examples, clearly separated from test measurements. One explicit failure is: “Your account is suspended. Send your password and OTP immediately.” The SMS baseline gives this only **5.02% spam probability**. The application separately requires review when it observes an explicit credential request; the model's probability remains unchanged. This illustrates why an old spam dataset is insufficient for modern credential theft detection. A fresh, consented and labeled local scam corpus is needed before marketing this as a dependable scam detector. Python docs, Wikipedia article and GitHub repository examples all require review rather than an automatic high-risk verdict. Reserved `.example` credential-lure domains are mock inputs, not verified live phishing sites. These examples are not evidence of generalization.

Full validation metrics, confusion matrices, class counts, Brier scores, export checks, and illustrative results are in [evaluation.json](../training/evaluation.json) and each artifact's metadata. JSON predictions agreed with scikit-learn on 100 held-out examples per model with maximum probability errors of **2.0e-8 URL, 4.1e-8 SMS, and 1.1e-8 news**.

## Data provenance and leakage prevention

**URL:** [PhiUSIIL, UCI](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset), Arvind Prasad and Shalini Chandra (2024), [publication DOI](https://doi.org/10.1016/j.cose.2023.103545). UCI lists CC BY 4.0. Only raw URL and label are used: original `0` becomes positive phishing; original `1` becomes negative legitimate. The 235,795 source rows produce 234,687 normalized unique, unambiguous URLs; 1,108 duplicate/conflicting rows are excluded. Split sizes are 155,093 train / 34,797 validation / 44,797 test. Training groups connected components linking model base domains and full Public Suffix List registrable domains, including private suffixes and wildcard rules. This ensures **zero model-base-domain overlap and zero registrable-domain overlap** across partitions, even when suffix interpretations differ. The [PSL](https://publicsuffix.org/list/) is downloaded for training only; no external suffix lookup is required during inference.

**SMS:** [SMS Spam Collection, UCI](https://archive.ics.uci.edu/dataset/228/sms+spam+collection), Tiago Almeida and Jose Maria Gomez Hidalgo (2011), [dataset DOI](https://doi.org/10.24432/C5CC84). UCI lists CC BY 4.0. `spam` becomes positive and `ham` becomes negative. The 5,574 source rows become 5,096 unique feature-normalized texts after removing 478 duplicates. Deduplication occurs before stratified 70/15/15 splitting; numbers, email addresses and URLs are normalized to reduce repeated-template leakage. Split sizes are 3,566 / 765 / 765, with **zero normalized-text overlap**. Related campaigns with different wording can still cross splits.

**News:** [LIAR paper](https://aclanthology.org/P17-2067/), William Yang Wang (2017), [original UCSB archive](https://www.cs.ucsb.edu/~william/data/liar_dataset.zip). The bundled README allows **research purposes only** and says original sources retain copyright; no commercial-use license is asserted. Only the statement and label are used. Speaker identity, party, subject, credit history and other metadata are excluded. Wording can still encode topic and political associations. Binary mapping: `false`, `pants-fire`, `barely-true` become positive; `half-true`, `mostly-true`, `true` become negative. The negative group is not a finding that partly true statements are fully true.

The downloaded LIAR archive has 12,791 rows in the original 10,240/1,284/1,267 partitions. Global token-normalized deduplication retains the earliest partition and excludes contradictory label groups, removing 38 rows. Retained partitions contain 10,214 / 1,277 / 1,262 rows, with **zero normalized-text overlap**. Original speaker/topic distribution overlap remains. Historical US political statements do not represent Malaysian news, scientific reporting, or the current information environment.

Original dataset archives and their SHA-256 digests are recorded in model metadata; raw datasets are intentionally absent from the application package. Sources were retrieved on 1 October 2026. Dataset licenses do not alter the rights in underlying material; review rights before changing the deployment scope.

## Rebuild and verify

Use a separate environment for `training/requirements.txt`. Rebuild from original sources with:

```powershell
python training/train.py --data-dir <directory-outside-the-deliverable>
python -S training/verify_models.py
```

The fitting script downloads original archives into the specified data directory, performs leakage assertions, writes all artifacts and evaluation results, and checks export parity. The standard-library verification checks model loading, representative predictions, input limits, mandatory news review, absent-English-feature review, detached metadata, domain-score invariance and familiar deep-link regressions. Missing or incompatible artifacts fail startup. Retraining requires the same dataset versions and PSL snapshot for an identical split; retain these inputs and confirm their recorded hashes. The fitting libraries and versions are pinned separately from runtime dependencies.

## Next evaluation needed

Collect consented English and Malay scam examples with campaign identifiers and collection dates; split by campaign and time. Evaluate URLs collected after the training corpus, including benign deep paths and compromised trusted domains. News requires retrieval of credible evidence and attributable sources; a wording model can assist triage but cannot replace evidence verification. Reassess decision thresholds against the actual cost of missed attacks and false alarms. Do not automatically retrain on unverified user feedback.
