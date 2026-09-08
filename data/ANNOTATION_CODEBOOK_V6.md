Ground-Truth Annotation Codebook V6

Scope

This codebook applies only to the corrected V6 frozen study baseline.

Source run: final_100_v6

Canonical population: 1,302 findings

Frozen annotation sample: 300 findings

Frozen sample SHA-256: e25c2870b96adc7e5eb9604d8c4320d7b478ec9ec011a1e3697a3b06288806d3

Sampling unit: canonical finding

Finding unit: canonical source statement plus security family

Scanner protocol: 1.3.0

Corpus protocol: 1.0.0

Coverage protocol: 1.0.0

The annotation task determines whether each sampled canonical finding represents a genuine security-relevant defect in the frozen repository revision. Scanner output is evidence of a detected pattern, not ground truth.

Labels

TRUE_BUG

Use TRUE_BUG when repository evidence supports that the flagged behavior is genuinely security-relevant and insufficiently mitigated.

Examples include:

externally influenced data reaches a dangerous operation without effective validation, sanitization, encoding, parameterization, containment, or equivalent protection;

an insecure configuration materially weakens security;

unsafe deserialization processes data that is not demonstrably trusted;

a weak cryptographic primitive is used for a security-sensitive purpose;

command, code, SQL, or similar execution can have its intended semantics altered by uncontrolled input;

surrounding code establishes a realistic security defect even if no working exploit is demonstrated.

A working exploit is not required.

FALSE_POSITIVE

Use FALSE_POSITIVE when the scanner pattern is present but repository evidence shows that the warned security defect is not present in context.

Examples include:

the relevant value is constant or cannot be influenced by an attacker;

effective validation, sanitization, encoding, parameterization, type restriction, or containment removes the warned risk;

a dangerous-looking API is used in a context that does not create the warned security property;

MD5 or SHA-1 is used only for a non-security purpose such as checksums, cache keys, ETags, deterministic filenames, or content deduplication;

SQL construction cannot be influenced by untrusted data;

unsafe deserialization is confined to a demonstrably trusted and integrity-protected boundary;

the scanner over-approximates framework, generated-code, syntax, or API behavior that is safe in context.

A finding is not a false positive merely because exploitation is difficult.

UNCERTAIN

Use UNCERTAIN only when the frozen repository evidence is insufficient to support either TRUE_BUG or FALSE_POSITIVE after reasonable investigation.

Examples include:

data origin cannot be resolved;

safety depends on deployment configuration absent from the repository;

a sanitizer or validator cannot be verified;

a required call boundary cannot be resolved from the frozen source;

security relevance depends on undocumented external guarantees.

UNCERTAIN is not a shortcut. The evidence procedure below must be attempted first.

Unresolved UNCERTAIN findings are reported separately and excluded from binary metrics unless later adjudicated.

Evidence Procedure

For every finding:

Read the security family, source statement, repository, file, and line location.

Open the exact frozen repository revision identified by the commit SHA.

Inspect the surrounding source context.

Inspect the enclosing function or method.

Trace relevant variables backward toward their origin.

Inspect validators, sanitizers, encoders, parameterization, type constraints, and guards.

Inspect direct callers or callees when needed.

Inspect nearby configuration or supporting code when security behavior depends on configuration.

Record the decisive evidence in the rationale.

Assign one label.

Do not assign a label from scanner severity, confidence, rule name, scanner count, or scanner message.

Security-Family Guidance

code-execution-exec

TRUE_BUG when exec or equivalent execution can consume uncontrolled or insufficiently constrained content.

FALSE_POSITIVE when executed content is demonstrably fixed, trusted, or otherwise cannot be influenced by an untrusted source.

code-execution-eval

TRUE_BUG when eval can process externally influenced or insufficiently constrained content.

FALSE_POSITIVE when the evaluated content is demonstrably fixed or safely constrained.

subprocess-shell-true

TRUE_BUG when shell interpretation is enabled and uncontrolled data can affect command text or shell semantics.

FALSE_POSITIVE when command content is fixed or all variable content is demonstrably unable to alter shell semantics.

Quoting alone does not automatically prove safety.

subprocess-execution

TRUE_BUG when untrusted data can alter the executable, arguments, or execution semantics in a security-relevant way.

FALSE_POSITIVE when executable selection and argument boundaries are safely controlled.

List-form invocation is useful evidence but is not automatically sufficient.

dynamic-sql

TRUE_BUG when untrusted data can alter SQL structure through interpolation, formatting, concatenation, or equivalent construction.

FALSE_POSITIVE when attacker-controlled values are effectively parameterized or all structural dynamic content is demonstrably trusted and constrained.

The presence of a database API does not by itself prove safety.

unsafe-deserialization

TRUE_BUG when an unsafe deserialization mechanism can process externally influenced or insufficiently trusted content.

FALSE_POSITIVE when repository evidence establishes a trusted and integrity-protected serialization boundary.

weak-hash

TRUE_BUG when a weak primitive is used for password security, authentication, security-token generation, security-sensitive integrity, signature-like checks, secret derivation, or another security property.

FALSE_POSITIVE when the hash is clearly used only for a non-security purpose.

disabled-cert-validation

TRUE_BUG when certificate verification is disabled for a connection that can carry production, user, credential, or security-sensitive traffic.

FALSE_POSITIVE when evidence clearly confines the behavior to an isolated test, mock, or otherwise non-security-sensitive connection.

Names such as test, dev, or local do not by themselves prove isolation.

hardcoded-temp-path

TRUE_BUG when predictable or shared temporary-path use creates a realistic race, overwrite, disclosure, privilege, or file-substitution risk.

FALSE_POSITIVE when secure creation semantics or other repository evidence removes the warned temporary-file risk.

Rationale Requirements

Every completed annotation must include a concise evidence-based rationale.

The rationale should state:

the relevant data source or security-sensitive purpose;

the dangerous sink or insecure behavior;

the decisive mitigation or missing mitigation;

any caller, validator, configuration, or guard that materially affected the decision.

Do not use rationales such as looks safe, scanner is wrong, probably vulnerable, Bandit says so, or Semgrep says so.

Blinding

The two annotator files intentionally omit scanner identity, scanner rule IDs, scanner severity, scanner confidence, scanner messages, raw alert IDs, and scanner count.

Annotators may use the security family and CWE to understand the security question, but they must decide the label from source evidence.

Annotators must not inspect the other annotator's labels or rationales before both independent passes are complete.

Annotators must not inspect LLM predictions or downstream model-evaluation results while constructing ground truth.

Independent Double Annotation

Two annotators independently label the same frozen 300 findings.

Each annotator records:

label

rationale

optional evidence_locations

Allowed labels are exactly:

TRUE_BUG

FALSE_POSITIVE

UNCERTAIN

No PENDING value may remain when an annotator completes their pass.

Adjudication

After both independent annotation passes are complete:

Join the files by finding_id.

Preserve both original annotator labels and rationales.

Accept matching labels provisionally.

Review every disagreement using repository evidence.

Record one final adjudicated_label.

Record one adjudication_rationale.

Leave a finding UNCERTAIN when evidence remains insufficient.

Never overwrite the original independent annotations.

Agreement Measurement

Compute raw agreement from the two independent pre-adjudication labels.

Compute Cohen's kappa using the three nominal categories:

TRUE_BUG

FALSE_POSITIVE

UNCERTAIN

Do not calculate kappa from adjudicated labels.

Report:

total agreements;

total disagreements;

raw agreement percentage;

Cohen's kappa;

category counts for each annotator;

number requiring adjudication;

number remaining UNCERTAIN after adjudication.

Binary Evaluation Dataset

For later binary evaluation:

TRUE_BUG is the positive class.

FALSE_POSITIVE is the negative class.

unresolved UNCERTAIN findings are excluded from binary metrics and reported separately.

Never silently map UNCERTAIN into a binary class.

Reproducibility Rules

Do not:

replace sampled findings after annotation begins;

change frozen repository SHAs;

regenerate the sample because of observed labels;

overwrite independent labels during adjudication;

expose one annotator's work to the other before both passes are complete;

use legacy 362, 300, 909, or 1,029 artifacts as V6 ground truth;

change labels to improve later model results.

Any post-pass correction must be logged with finding ID, previous value, new value, reason, and date.

Completion Criteria

Ground-truth construction is complete only when:

Annotator 1 has completed all 300 findings;

Annotator 2 has completed all 300 findings;

every completed annotation has a rationale;

pre-adjudication agreement and Cohen's kappa have been calculated;

all disagreements have been adjudicated or explicitly retained as UNCERTAIN;

final adjudicated labels and rationales are complete;

no PENDING remains in the completed annotation outputs;

the frozen source sample remains unchanged.