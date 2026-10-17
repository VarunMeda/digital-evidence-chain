# MySQL migrations

Run the existing schema/bootstrap scripts first, then apply `001_advanced_features.sql` and `002_lifecycle_hardening.sql` against `digital_evidence_chain`. Both migrations are additive with respect to data: they do not drop tables or delete records. The second migration replaces only the named procedures/triggers and adds the original-hash protection trigger.

`002_lifecycle_hardening.sql` protects `evidence.original_sha256` from ordinary SQL updates and makes `sp_transfer_custody` and `sp_close_case` authoritative for their corresponding workflows. Both procedures lock the relevant rows, write their audit event in the same SQL transaction, and roll back on errors. The protection is against application/database users allowed to execute the trigger; a privileged DBA can still disable or replace database objects.

The closure policy permits evidence retained by a current custodian or explicitly in storage/released state. It rejects pending/in-progress analysis, unresolved integrity alerts, flagged or under-analysis evidence, and evidence without a valid custody/storage state. This is the project's documented interpretation of the abstract's custody and release requirements.
