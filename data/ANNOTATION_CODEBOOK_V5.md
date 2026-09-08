Ground-Truth Annotation Codebook V5

Scope

This codebook applies to the frozen annotation sample:

Source run: final_100_v5_complete

Population: 1,414 canonical findings

Frozen sample: 300 canonical findings

Sample SHA-256: 4d7537fd44909fb36ef5f0a2e9a44b7162f82a069d26fb7ce52dd7eb4bd7255e

Sampling unit: canonical finding

Annotation unit: one canonical source statement plus one security family

The purpose of annotation is to determine whether each canonical SAST finding represents a real security-relevant defect in the frozen repository snapshot.

Scanner output is evidence that a pattern was detected. It is not ground truth.

Allowed Labels

TRUE_BUG

Use TRUE_BUG when the available repository evidence supports that the flagged behavior is genuinely security-relevant and insufficiently mitigated.

A finding can be labeled TRUE_BUG when one or more of the following is established:

untrusted or externally influenced data can reach the dangerous operation without an effective validation, sanitization, encoding, parameterization, or containment step;

a dangerous operation is performed with an insecure configuration that materially weakens security;

unsafe deserialization is performed on data that is not demonstrably trusted;

a weak cryptographic primitive is used for a security-sensitive purpose;

command, code, SQL, or similar execution is constructed from uncontrolled data in a way that can alter intended semantics;

the surrounding code demonstrates a realistic security-relevant misuse even if an exploit path cannot be fully demonstrated from the single statement alone.

Do not require proof of a working exploit. The annotation target is whether the code constitutes a genuine security defect under the repository evidence available.

FALSE_POSITIVE

Use FALSE_POSITIVE when the scanner pattern is present but repository evidence shows that the flagged behavior is not a security defect in context.

Typical reasons include:

the relevant value is constant or otherwise not attacker-controlled;

input is effectively validated, constrained, encoded, sanitized, parameterized, or safely tokenized before reaching the operation;

the dangerous-looking API is used for a non-security-sensitive purpose that does not create the warned security risk;

a weak hash is used only for a non-security purpose such as a checksum, content fingerprint, cache key, ETag, or deduplication identifier;

certificate verification is disabled only in a clearly isolated non-security context that cannot affect production security;

SQL construction is not influenced by untrusted data or is subsequently handled in a way that prevents injection;

deserialization input is demonstrably trusted and integrity-protected within the examined program context;

the alert results from syntax, framework, generated-code, or API patterns that the scanner over-approximates but which are safe in the actual context.

A finding is not a false positive merely because exploitation appears difficult.

UNCERTAIN

Use UNCERTAIN only when the available frozen repository evidence is insufficient to justify either TRUE_BUG or FALSE_POSITIVE.

Examples include:

data origin cannot be established after reasonable tracing;

safety depends on deployment configuration that is absent from the repository;

a sanitizer or validator is referenced but its behavior cannot be verified;

a call crosses a boundary that cannot be resolved from the frozen source;

security relevance depends on undocumented external guarantees.

UNCERTAIN is not a convenience label. Annotators must first perform the evidence checks described below.

Unresolved UNCERTAIN findings are reported separately and excluded from binary precision and false-positive-rate calculations unless later adjudicated.

Evidence Procedure

For each finding, inspect evidence in this order:

Read the canonical statement and security family.

Inspect the surrounding source context.

Inspect the enclosing function or method.

Trace relevant variables backward to their origin.

Inspect validation, sanitization, encoding, type coercion, parameterization, or guards.

Inspect direct callers or callees when necessary to determine data origin or security meaning.

Inspect repository configuration or nearby supporting code when the finding depends on configuration.

Record the decisive evidence in the rationale.

Do not assign a label from the scanner rule name, severity, confidence, or scanner count alone.

Security-Family Guidance

code-execution-exec

TRUE_BUG when exec or equivalent code execution can consume uncontrolled or insufficiently constrained content.

FALSE_POSITIVE when executed content is demonstrably fixed, internally generated from trusted constants, or otherwise incapable of being influenced by an untrusted source.

code-execution-eval

TRUE_BUG when eval can process data that is externally influenced or not strictly constrained.

FALSE_POSITIVE when the evaluated expression is demonstrably fixed or constrained to a safe internal representation that cannot be altered by an untrusted source.

subprocess-shell-true

TRUE_BUG when shell interpretation is enabled and uncontrolled data can affect the command string or shell semantics.

FALSE_POSITIVE when the command is fixed and all variable content is demonstrably safe from shell interpretation.

Shell quoting must be evaluated in context. The presence of a quoting function alone is not sufficient to prove safety.

subprocess-execution

TRUE_BUG when untrusted data can alter the executed program, arguments, or execution semantics in a security-relevant way.

FALSE_POSITIVE when argument boundaries and executable selection are safely controlled and untrusted values cannot alter command semantics.

List-form subprocess invocation is relevant evidence but does not automatically make every invocation safe.

dynamic-sql

TRUE_BUG when untrusted data can alter SQL structure through string construction, interpolation, concatenation, or equivalent dynamic construction.

FALSE_POSITIVE when dynamic content is demonstrably trusted, strictly constrained to a safe domain, or the query uses effective parameterization for attacker-controlled values.

Do not mark a finding safe merely because the final query is executed through a database API.

unsafe-deserialization

TRUE_BUG when pickle or another unsafe deserialization mechanism can process content that is externally influenced or whose trust cannot be established.

FALSE_POSITIVE when the serialized object is demonstrably produced and consumed entirely inside a trusted boundary with appropriate integrity assumptions supported by repository evidence.

weak-hash

TRUE_BUG when MD5, SHA-1, or another weak primitive is used for a security-sensitive property such as password protection, authentication, signature-like integrity, secret derivation, or security token generation.

FALSE_POSITIVE when the hash is clearly used only for a non-security purpose such as checksums, cache identity, ETags, deterministic filenames, or content deduplication.

disabled-cert-validation

TRUE_BUG when certificate verification is disabled for a connection that can carry production, user, credential, or security-sensitive traffic.

FALSE_POSITIVE when repository evidence clearly limits the behavior to a controlled local test, mock, or otherwise non-security-sensitive connection.

Do not assume that a variable named test, dev, or local proves isolation.

hardcoded-temp-path

TRUE_BUG when use of a predictable or shared temporary path creates a realistic race, overwrite, disclosure, privilege, or file-substitution risk.

FALSE_POSITIVE when the path is not actually used unsafely, is protected by secure creation semantics, or repository evidence otherwise removes the warned temporary-file risk.

Rationale Requirements

Every non-PENDING annotation must have a concise evidence-based rationale.

A useful rationale should state:

the relevant data source or security-sensitive purpose;

the dangerous sink or insecure behavior;

the mitigation or missing mitigation that determines the label;

any caller, validator, configuration, or guard that was decisive.

Avoid rationales such as:

looks safe

scanner is wrong

probably vulnerable

Bandit says so

Semgrep says so

The rationale must be understandable without seeing the annotator's private notes.

Independent Double Annotation

Two annotators must label the same 300 frozen findings independently.

Annotator 1 must not see Annotator 2's labels or rationales before both annotation passes are complete.

Annotator 2 must not see Annotator 1's labels or rationales before both annotation passes are complete.

Neither annotator should see LLM predictions or later model-evaluation results while establishing ground truth.

The frozen finding identifiers and source snapshot must not change during annotation.

Adjudication

After both independent annotation passes are complete:

Compare the two labels.

Findings with identical labels are provisionally accepted.

Findings with different labels are reviewed during adjudication.

Adjudication must examine the repository evidence rather than choose a label by majority or scanner vote.

Record one final adjudicated_label.

Record one adjudication_rationale.

Preserve both original annotator labels permanently.

If the evidence remains insufficient after adjudication, the final label may remain UNCERTAIN.

Agreement Measurement

Compute raw agreement as:

agreements / 300

Compute Cohen's kappa on the two independent pre-adjudication labels.

Use the three nominal categories:

TRUE_BUG

FALSE_POSITIVE

UNCERTAIN

Do not compute kappa from adjudicated labels.

Report:

number of agreements;

number of disagreements;

raw agreement percentage;

Cohen's kappa;

category counts for each annotator;

number of findings requiring adjudication;

number of findings remaining UNCERTAIN after adjudication.

Binary Evaluation Dataset

For later scanner and LLM performance calculations:

TRUE_BUG is the positive class;

FALSE_POSITIVE is the negative class;

unresolved UNCERTAIN findings are excluded from binary metrics and reported separately.

Do not silently convert UNCERTAIN to either binary class.

Reproducibility Rules

Do not:

replace sampled findings after viewing labels;

change the frozen repository SHAs;

regenerate the sample after annotation begins;

overwrite the original annotator labels during adjudication;

change a rationale to make later model results appear better;

use legacy 300-row, 909-row, 1,029-row, or synthetic 362-alert artifacts as ground truth for this study.

Any correction to an annotation after the initial annotation pass must be logged with the finding ID, previous value, new value, reason, and date.

Completion Criteria

Ground-truth construction is complete only when:

all 300 findings have an Annotator 1 label and rationale;

all 300 findings have an Annotator 2 label and rationale;

pre-adjudication agreement and Cohen's kappa have been computed;

all disagreements have been adjudicated or explicitly left UNCERTAIN;

final adjudicated labels and rationales are complete;

no PENDING value remains in the completed annotation dataset;

annotation outputs are versioned and committed without modifying the original frozen sample.