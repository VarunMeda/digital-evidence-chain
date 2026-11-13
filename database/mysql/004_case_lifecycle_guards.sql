-- 004_case_lifecycle_guards.sql
-- Database-level guards for custody/access consistency and closed cases.

DROP TRIGGER IF EXISTS trg_case_member_no_active_custody_delete;
DELIMITER $$
CREATE TRIGGER trg_case_member_no_active_custody_delete
BEFORE DELETE ON case_members
FOR EACH ROW
BEGIN
  DECLARE v_held BIGINT DEFAULT 0;
  SELECT COUNT(*) INTO v_held FROM evidence
  WHERE case_id = OLD.case_id AND current_custodian = OLD.user_id;
  IF v_held > 0 THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Cannot remove case access while the user currently holds evidence in this case';
  END IF;
END$$
DELIMITER ;

DROP TRIGGER IF EXISTS trg_evidence_closed_case_insert;
DELIMITER $$
CREATE TRIGGER trg_evidence_closed_case_insert
BEFORE INSERT ON evidence
FOR EACH ROW
BEGIN
  DECLARE v_status VARCHAR(30);
  SELECT status INTO v_status FROM cases WHERE case_id = NEW.case_id;
  IF v_status = 'CLOSED' THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Case is closed; evidence cannot be added';
  END IF;
END$$
DELIMITER ;

DROP TRIGGER IF EXISTS trg_evidence_closed_case_custody_update;
DELIMITER $$
CREATE TRIGGER trg_evidence_closed_case_custody_update
BEFORE UPDATE ON evidence
FOR EACH ROW
BEGIN
  DECLARE v_status VARCHAR(30);
  IF NOT (NEW.current_custodian <=> OLD.current_custodian) THEN
    SELECT status INTO v_status FROM cases WHERE case_id = NEW.case_id;
    IF v_status = 'CLOSED' THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Case is closed; custody cannot change';
    END IF;
  END IF;
END$$
DELIMITER ;

DROP TRIGGER IF EXISTS trg_custody_closed_case_insert;
DELIMITER $$
CREATE TRIGGER trg_custody_closed_case_insert
BEFORE INSERT ON custody_records
FOR EACH ROW
BEGIN
  DECLARE v_status VARCHAR(30);
  SELECT c.status INTO v_status FROM evidence e JOIN cases c ON c.case_id = e.case_id WHERE e.evidence_id = NEW.evidence_id;
  IF v_status = 'CLOSED' THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Case is closed; custody events cannot be added';
  END IF;
END$$
DELIMITER ;

DROP TRIGGER IF EXISTS trg_analysis_closed_case_insert;
DELIMITER $$
CREATE TRIGGER trg_analysis_closed_case_insert
BEFORE INSERT ON analysis_records
FOR EACH ROW
BEGIN
  DECLARE v_status VARCHAR(30);
  SELECT c.status INTO v_status FROM evidence e JOIN cases c ON c.case_id = e.case_id WHERE e.evidence_id = NEW.evidence_id;
  IF v_status = 'CLOSED' THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Case is closed; analysis cannot be created';
  END IF;
END$$
DELIMITER ;

DROP TRIGGER IF EXISTS trg_analysis_closed_case_update;
DELIMITER $$
CREATE TRIGGER trg_analysis_closed_case_update
BEFORE UPDATE ON analysis_records
FOR EACH ROW
BEGIN
  DECLARE v_status VARCHAR(30);
  SELECT c.status INTO v_status FROM evidence e JOIN cases c ON c.case_id = e.case_id WHERE e.evidence_id = NEW.evidence_id;
  IF v_status = 'CLOSED' THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Case is closed; analysis cannot be changed';
  END IF;
END$$
DELIMITER ;
