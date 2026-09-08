Legacy Dataset Provenance

Status

The research repository now uses final_100_v5_complete as the authoritative static-analysis baseline.

This baseline contains 100 successfully scanned repositories, 2,491 raw scanner alerts, 1,414 canonical findings, 12,519 candidate Python files, and 12,515 cross-scanner comparable files. The four non-comparable files are explicitly recorded parser incompatibilities. These counts are scanner observations, not confirmed vulnerabilities or ground-truth labels.

Legacy Artifact Classification

Legacy count or artifact

Provenance

Status

362 alerts

Produced by the recovered synthetic/template-based mining pipeline. The pipeline generated a small set of representative Python modules and mapped the 100 repository identities to those templates rather than scanning the real repositories. results_dataset/alert_distribution_by_cwe.xlsx sums to 362 alerts.

Retain only for provenance. Do not use as empirical evidence from real repositories.

300-row sample

Stratified sample from the synthetic 362-alert pipeline. The sample contains only five synthetic filenames and all annotation fields remain PENDING.

Not ground truth. Retain only for provenance.

909 alerts

Legacy RQ1 summary total. The seven values in data/rq1_domain_distribution_table.xlsx sum to 909. This distribution does not match the 1,029-row inventory and no verified raw source currently links the 909 total to a reproducible scanner run.

Retire from current analysis and claims.

1,029-row inventory

Separate legacy constructed inventory covering 100 repository identities. It contains generated-looking worker paths, no frozen commit SHAs, and pre-populated labels of 678 FALSE_POSITIVE and 351 TRUE_BUG.

Not accepted as verified ground truth or as the current scanner dataset. Retain only for provenance unless independent annotation evidence is recovered.

results_main_study/*

Metrics and significance outputs from the legacy workflow. The available 300-row annotation sheet is entirely PENDING, and the repository does not currently provide raw model predictions that independently reproduce these metrics.

Retire from current empirical claims until regenerated from the new baseline and real annotations.

results_pilot/*

Legacy pilot outputs without sufficient current provenance to support the final study.

Historical only; regenerate if a pilot analysis is required.

Relationships Established by the Audit

The 300-row sample is not a sample of the 1,029-row inventory. Matching on their shared candidate identifying fields produced zero matching rows.

The synthetic 362-alert pipeline is linked to the old 300-row sample by its generated source filenames. The recovered historical pipeline generated representative modules including web_api_routes.py, network_client.py, cli_executor.py, cache_serializer.py, security_crypto_utils.py, and file_manager.py; the old 300-row sample contains findings from the first five of these generated modules.

The 909 figure is a legacy summary count rather than a row count of a discovered raw dataset. Its domain totals are 188 + 53 + 90 + 96 + 167 + 143 + 172 = 909.

The 1,029-row inventory is a different legacy artifact. Its current domain distribution sums to 1,029 and therefore cannot be the direct source of the stored 909-domain summary table.

Current Research Rule

Use the frozen final_100_v5_complete baseline for all subsequent dataset construction, sampling, annotation, slicing, model evaluation, and statistical analysis.

Do not report 362, 909, or 1,029 as the number of findings in the current real-repository experiment.

Do not report the 1,029 inventory's TRUE_BUG or FALSE_POSITIVE labels as verified ground truth.

Do not report precision, false-positive reduction, agreement, or McNemar results from the legacy result files as findings of the repaired study unless they are independently regenerated from the frozen baseline and documented annotation/model-prediction records.