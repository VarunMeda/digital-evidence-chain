# MySQL migrations

Run the existing schema/bootstrap scripts first, then apply `001_advanced_features.sql`, `002_lifecycle_hardening.sql`, `003_case_access_control.sql`, and `004_case_lifecycle_guards.sql` in order against `digital_evidence_chain`. All migrations are additive with respect to data: they do not drop tables or delete records. The second migration replaces only the named procedures/triggers and adds the original-hash protection trigger.

`004_case_lifecycle_guards.sql` adds database triggers that block removing a member who is the current custodian of evidence in the case, and block evidence insertion, custody changes, and analysis creation/updates while the case is `CLOSED`. API routes enforce the same rules with clearer error messages.

`003_case_access_control.sql` adds `case_members` and backfills existing creators, evidence registrants, custodians, and analysts. Triggers keep memberships in sync for direct SQL writes (seed scripts, imports), and the API enforces the same rule for every case, evidence, analysis, artifact, graph, custody, alert, and dashboard request. Administrators remain globally authorized.

`002_lifecycle_hardening.sql` protects `evidence.original_sha256` from ordinary SQL updates and makes `sp_transfer_custody` and `sp_close_case` authoritative for their corresponding workflows. Both procedures lock the relevant rows, write their audit event in the same SQL transaction, and roll back on errors. The protection is against application/database users allowed to execute the trigger; a privileged DBA can still disable or replace database objects.

The closure policy permits evidence retained by a current custodian or explicitly in storage/released state. It rejects pending/in-progress analysis, unresolved integrity alerts, flagged or under-analysis evidence, and evidence without a valid custody/storage state. This is the project's documented interpretation of the abstract's custody and release requirements.
