# Finding decision reason codes

Finding approval and rejection require both a closed structured `reason_code` and a
free-text `rationale`. The code makes review outcomes aggregatable; it never replaces
the approver's explanation. The backend rejects a code that is unknown, absent, or
incompatible with the selected decision.

| Decision | Reason code | Meaning |
|---|---|---|
| Approve | `human_confirmed` | A human approver reviewed the verification chain and confirmed the finding. |
| Reject | `not_a_real_exploit` | The reviewed behavior does not establish an exploit. |
| Reject | `insufficient_evidence` | The durable evidence is insufficient to accept the finding. |
| Reject | `duplicate_finding` | The finding duplicates an already tracked finding. |
| Reject | `outside_authorized_scope` | The observation is outside the exact authorized target/surface scope. |

Existing rows may have a null code because migration `0005` made the column nullable.
New approve/reject commands cannot create another null-coded row. Resolution remains a
separate permissioned action with its required rationale and no review reason code.

## Read-boundary residual

Decision history is batch-loaded once and capped at the newest 50 events per projected
finding. The top-level findings collection remains uncapped because v1 has no stable
cursor or pagination contract. Adding silent truncation would make finding visibility
and aggregate counts misleading; pagination is follow-up contract work rather than a
release-time response-shape change.
