# MySQL migrations

Run the existing schema/bootstrap scripts first, then apply `001_advanced_features.sql` once against `digital_evidence_chain`. The migration is additive apart from replacing views/procedures and installing immutable-audit triggers. It does not drop tables or delete records.

The application still validates case closure and custody transitions in Node. The stored procedures provide database-level demonstrations and concurrency-safe locking for evaluation.
