USE digital_evidence_chain;

-- Additive indexes for the application's real list and history queries.
CREATE INDEX idx_evidence_case_status ON evidence (case_id, status, registered_at);

CREATE OR REPLACE VIEW v_case_summary AS
SELECT c.case_id, c.case_number, c.title, c.status, c.created_at, c.closed_at,
       COUNT(e.evidence_id) AS evidence_count,
       SUM(e.status = 'FLAGGED') AS flagged_evidence_count,
       SUM(e.status = 'UNDER_ANALYSIS') AS under_analysis_count,
       (SELECT COUNT(*) FROM integrity_alerts ia JOIN evidence ie ON ie.evidence_id = ia.evidence_id WHERE ie.case_id = c.case_id AND ia.status <> 'RESOLVED') AS unresolved_alert_count
FROM cases c LEFT JOIN evidence e ON e.case_id = c.case_id
GROUP BY c.case_id, c.case_number, c.title, c.status, c.created_at, c.closed_at;

CREATE OR REPLACE VIEW v_custody_history AS
SELECT cr.custody_id, cr.evidence_id, e.evidence_code, cr.event_type,
       fu.full_name AS from_user_name, tu.full_name AS to_user_name,
       pu.full_name AS performed_by_name, cr.reason, cr.location, cr.event_time
FROM custody_records cr JOIN evidence e ON e.evidence_id = cr.evidence_id
LEFT JOIN users fu ON fu.user_id = cr.from_user LEFT JOIN users tu ON tu.user_id = cr.to_user
JOIN users pu ON pu.user_id = cr.performed_by;

DROP TRIGGER IF EXISTS trg_audit_no_update;
DROP TRIGGER IF EXISTS trg_audit_no_delete;
DELIMITER $$
CREATE TRIGGER trg_audit_no_update BEFORE UPDATE ON audit_logs FOR EACH ROW
BEGIN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Audit records are immutable'; END$$
CREATE TRIGGER trg_audit_no_delete BEFORE DELETE ON audit_logs FOR EACH ROW
BEGIN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Audit records cannot be deleted'; END$$

DROP PROCEDURE IF EXISTS sp_transfer_custody$$
CREATE PROCEDURE sp_transfer_custody(IN p_evidence_id BIGINT, IN p_from_user BIGINT, IN p_to_user BIGINT, IN p_performed_by BIGINT, IN p_reason TEXT, IN p_location VARCHAR(255))
BEGIN
  DECLARE v_current BIGINT;
  DECLARE v_status VARCHAR(30);
  START TRANSACTION;
  SELECT current_custodian, status INTO v_current, v_status FROM evidence WHERE evidence_id = p_evidence_id FOR UPDATE;
  IF v_current IS NULL OR v_current <> p_from_user OR v_status IN ('RELEASED','FLAGGED') THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Custody precondition failed';
  END IF;
  UPDATE evidence SET current_custodian = p_to_user, status = 'IN_CUSTODY' WHERE evidence_id = p_evidence_id;
  INSERT INTO custody_records (evidence_id, event_type, from_user, to_user, performed_by, reason, location) VALUES (p_evidence_id, 'TRANSFERRED', p_from_user, p_to_user, p_performed_by, p_reason, p_location);
  COMMIT;
END$$

DROP PROCEDURE IF EXISTS sp_close_case$$
CREATE PROCEDURE sp_close_case(IN p_case_id BIGINT)
BEGIN
  IF EXISTS (SELECT 1 FROM analysis_records a JOIN evidence e ON e.evidence_id=a.evidence_id WHERE e.case_id=p_case_id AND a.status IN ('PENDING','IN_PROGRESS')) THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Case has incomplete analysis'; END IF;
  IF EXISTS (SELECT 1 FROM integrity_alerts i JOIN evidence e ON e.evidence_id=i.evidence_id WHERE e.case_id=p_case_id AND i.status <> 'RESOLVED') THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Case has unresolved integrity alerts'; END IF;
  UPDATE cases SET status='CLOSED', closed_at=CURRENT_TIMESTAMP WHERE case_id=p_case_id;
END$$
DELIMITER ;
