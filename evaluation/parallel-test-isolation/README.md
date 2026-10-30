# Parallel test isolation

Claim 4 correctness maintenance: RapidProbe rejection tests retain their owned
target reservations through the exact error checks. Four quiescent native
campaigns share the existing bounded prefixed-pun fresh-process helper, keeping
all native bodies and assertions unchanged while isolating their address spaces.
The workspace retains 316 test threads; no workspace serialization is added.

The [RapidProbe-only run](results-2eedfe4/README.md) retains two subsequent
quiescent allocation failures. After the isolation fix, the [full run at
d3f4701](results-d3f4701/README.md) passes 3,649 workspace tests with zero failures
and 37 ignored, plus 1,039 serial launch tests. Both records include exact
revisions, commands, hardware, reservations, load and raw-log hashes. They use
the existing tracked validation driver; raw logs remain ignored.
