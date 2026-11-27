# Registered dispatch and causal feature history

RegisteredEvaluator selects count, cardinality, ordered temporal or unordered temporal by registered mode; it rejects unknown modes and mismatched job scope. Each evaluator independently verifies its immutable rule definition. The test uses mocked callbacks to verify dispatch; the individual real Java bridges remain exercised by separate end-to-end simulated Indexer tests.

FeatureHistory supplies pure point-in-time contracts around the existing EntityRisk and BehaviourBaseline engines. Behaviour uses complete, equal-duration, non-overlapping historic feature windows in the same scope/version/name, with approval available by the current window start. Current feature availability is checked against the evaluation time. Exact repeated receipts are deduplicated; conflicting receipts and mismatched scope are withheld. Risk filters signals by availability, deduplicates signal identity and withholds the numeric score for incomplete or conflicting ledgers. Both return admitted receipt references.

No trusted provenance authority, storage, feature extraction, ledger completeness proof, persisted lifecycle or native risk/UEBA dispatch has been implemented. The receipt strings and completeness inputs are provided by the caller, not authenticated. No production risk scores are emitted. No change to incident management or Wazuh runtime.

Local verification: python3 -m unittest discover -s tools/wade/native -q, 40 tests passed, including the new feature Java harness with 11 assertions. JDK 21, compile target 17, warnings as errors. Fake Indexer only; no real cluster or runtime tests. This is incremental qualification of the isolated prototype.
