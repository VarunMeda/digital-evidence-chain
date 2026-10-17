USE digital_evidence_chain;

-- The registration hash is the chain-of-custody baseline. Application code never
-- updates it, and this trigger prevents ordinary SQL updates from replacing it.
DROP TRIGGER IF EXISTS trg_evidence_original_sha256_immutable;
DELIMITER $$
CREATE TRIGGER trg_evidence_original_sha256_immutable
BEFORE UPDATE ON evidence
FOR EACH ROW
BEGIN
  IF NOT (NEW.original_sha256 <=> OLD.original_sha256) THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Original evidence SHA-256 is immutable';
  END IF;
END$$

DROP PROCEDURE IF EXISTS sp_transfer_custody$$
CREATE PROCEDURE sp_transfer_custody(
  IN p_evidence_id BIGINT,
  IN p_from_user BIGINT,
  IN p_to_user BIGINT,
  IN p_performed_by BIGINT,
  IN p_reason TEXT,
  IN p_location VARCHAR(255)
)
BEGIN
  DECLARE v_current BIGINT;
  DECLARE v_status VARCHAR(30);
  DECLARE v_exists BIGINT DEFAULT 0;

  DECLARE EXIT HANDLER FOR SQLEXCEPTION
  BEGIN
    ROLLBACK;
    RESIGNAL;
  END;

  START TRANSACTION;
  SELECT current_custodian, status INTO v_current, v_status
  FROM evidence WHERE evidence_id = p_evidence_id FOR UPDATE;

  IF v_current IS NULL THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Evidence not found or has no current custodian';
  END IF;
  IF v_current <> p_from_user OR v_current <> p_performed_by THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Custody precondition failed: current custodian is different';
  END IF;
  IF p_to_user = p_from_user THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Destination custodian must be different';
  END IF;
  IF v_status IN ('RELEASED', 'FLAGGED') THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Evidence cannot be transferred in its current state';
  END IF;

  SELECT COUNT(*) INTO v_exists FROM users
  WHERE user_id = p_to_user AND status = 'ACTIVE' AND role = 'CUSTODIAN';
  IF v_exists = 0 THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Destination user must be an active custodian';
  END IF;

  UPDATE evidence SET current_custodian = p_to_user, status = 'IN_CUSTODY'
  WHERE evidence_id = p_evidence_id;
  INSERT INTO custody_records (evidence_id, event_type, from_user, to_user, performed_by, reason, location)
  VALUES (p_evidence_id, 'TRANSFERRED', p_from_user, p_to_user, p_performed_by, p_reason, p_location);
  INSERT INTO audit_logs (user_id, action, entity_type, entity_id, details)
  VALUES (p_performed_by, 'CUSTODY_TRANSFERRED', 'EVIDENCE', p_evidence_id,
          JSON_OBJECT('from_user_id', p_from_user, 'to_user_id', p_to_user,
                      'reason', p_reason, 'location', p_location));
  COMMIT;
END$$

DROP PROCEDURE IF EXISTS sp_close_case$$
CREATE PROCEDURE sp_close_case(IN p_case_id BIGINT, IN p_actor BIGINT)
BEGIN
  DECLARE v_status VARCHAR(30);
  DECLARE v_count BIGINT DEFAULT 0;

  DECLARE EXIT HANDLER FOR SQLEXCEPTION
  BEGIN
    ROLLBACK;
    RESIGNAL;
  END;

  START TRANSACTION;
  SELECT status INTO v_status FROM cases WHERE case_id = p_case_id FOR UPDATE;
  IF v_status IS NULL THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Case not found';
  END IF;
  IF v_status = 'CLOSED' THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Case is already closed';
  END IF;

  SELECT COUNT(*) INTO v_count
  FROM analysis_records a JOIN evidence e ON e.evidence_id = a.evidence_id
  WHERE e.case_id = p_case_id AND a.status IN ('PENDING', 'IN_PROGRESS');
  IF v_count > 0 THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Case has incomplete analysis';
  END IF;

  SELECT COUNT(*) INTO v_count
  FROM integrity_alerts i JOIN evidence e ON e.evidence_id = i.evidence_id
  WHERE e.case_id = p_case_id AND i.status <> 'RESOLVED';
  IF v_count > 0 THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Case has unresolved integrity alerts';
  END IF;

  SELECT COUNT(*) INTO v_count FROM evidence
  WHERE case_id = p_case_id
    AND (status IN ('FLAGGED', 'UNDER_ANALYSIS')
         OR (current_custodian IS NULL AND status NOT IN ('IN_STORAGE', 'RELEASED')));
  IF v_count > 0 THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Case has evidence in an invalid lifecycle or custody state';
  END IF;

  UPDATE cases SET status = 'CLOSED', closed_at = CURRENT_TIMESTAMP
  WHERE case_id = p_case_id;
  INSERT INTO audit_logs (user_id, action, entity_type, entity_id, details)
  VALUES (p_actor, 'CASE_STATUS_CHANGED', 'CASE', p_case_id,
          JSON_OBJECT('status', 'CLOSED'));
  COMMIT;
END$$
DELIMITER ;
