## Core pair verification

`run_core_pairs.py` defines the bounded original/core comparison for all 176 cases in each of the four null-hook cells. `audit_core_pairs.py` independently checks the saved architectural states, route observations and input identities. Both require explicit source and build activation; their unset activation constants deliberately refuse execution. The current source alone supplies no native result.

`test_core_pair_profiles.py` exercises the auditor with synthetic valid inputs and corruptions; [all eight methods passed](../reproductions/core-auditor-pure-041bd4a/README.md) in the recorded run. The separate [canonical-verifier controls](../reproductions/canonical-verifier-pure-50c0715/README.md) check source correspondence and build-reader selection. These controls validate the checking tools; the 704 native core pairs and 2,112 recording obligations remain pending.
