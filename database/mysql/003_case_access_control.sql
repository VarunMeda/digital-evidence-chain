-- 003_case_access_control.sql
-- Case-scoped access control. Administrators keep global access; every other
-- user can only read a case and its evidence when their user_id is present in
-- case_members for that case.

CREATE TABLE IF NOT EXISTS case_members (
  case_id BIGINT UNSIGNED NOT NULL,
  user_id BIGINT UNSIGNED NOT NULL,
  access_level ENUM('VIEW','MANAGE') NOT NULL DEFAULT 'VIEW',
  added_by BIGINT UNSIGNED NULL,
  added_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (case_id, user_id),
  CONSTRAINT fk_case_members_case FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE,
  CONSTRAINT fk_case_members_user FOREIGN KEY (user_id) REFERENCES users(user_id),
  CONSTRAINT fk_case_members_added_by FOREIGN KEY (added_by) REFERENCES users(user_id),
  INDEX idx_case_members_user (user_id)
) ENGINE=InnoDB;

-- Backfill existing records so the current users keep the access they had.
INSERT IGNORE INTO case_members (case_id, user_id, access_level, added_by)
SELECT c.case_id, c.created_by, 'MANAGE', c.created_by FROM cases c WHERE c.created_by IS NOT NULL;

INSERT IGNORE INTO case_members (case_id, user_id, access_level, added_by)
SELECT e.case_id, e.registered_by, 'VIEW', e.registered_by FROM evidence e WHERE e.registered_by IS NOT NULL;

INSERT IGNORE INTO case_members (case_id, user_id, access_level, added_by)
SELECT e.case_id, e.current_custodian, 'VIEW', e.registered_by FROM evidence e WHERE e.current_custodian IS NOT NULL;

INSERT IGNORE INTO case_members (case_id, user_id, access_level, added_by)
SELECT e.case_id, cr.from_user, 'VIEW', cr.performed_by FROM custody_records cr JOIN evidence e ON e.evidence_id = cr.evidence_id WHERE cr.from_user IS NOT NULL;

INSERT IGNORE INTO case_members (case_id, user_id, access_level, added_by)
SELECT e.case_id, cr.to_user, 'VIEW', cr.performed_by FROM custody_records cr JOIN evidence e ON e.evidence_id = cr.evidence_id WHERE cr.to_user IS NOT NULL;

INSERT IGNORE INTO case_members (case_id, user_id, access_level, added_by)
SELECT e.case_id, cr.performed_by, 'VIEW', cr.performed_by FROM custody_records cr JOIN evidence e ON e.evidence_id = cr.evidence_id WHERE cr.performed_by IS NOT NULL;

INSERT IGNORE INTO case_members (case_id, user_id, access_level, added_by)
SELECT e.case_id, a.analyst_id, 'VIEW', a.analyst_id FROM analysis_records a JOIN evidence e ON e.evidence_id = a.evidence_id WHERE a.analyst_id IS NOT NULL;

-- Provision future memberships automatically for paths that write directly to
-- MySQL (seed scripts, imports) as well as for the normal API workflow.
DROP TRIGGER IF EXISTS trg_case_creator_member;
DELIMITER $$
CREATE TRIGGER trg_case_creator_member
AFTER INSERT ON cases
FOR EACH ROW
BEGIN
  INSERT IGNORE INTO case_members (case_id, user_id, access_level, added_by)
  VALUES (NEW.case_id, NEW.created_by, 'MANAGE', NEW.created_by);
END$$
DELIMITER ;

DROP TRIGGER IF EXISTS trg_evidence_members_on_insert;
DELIMITER $$
CREATE TRIGGER trg_evidence_members_on_insert
AFTER INSERT ON evidence
FOR EACH ROW
BEGIN
  IF NEW.registered_by IS NOT NULL THEN
    INSERT IGNORE INTO case_members (case_id, user_id, access_level, added_by)
    VALUES (NEW.case_id, NEW.registered_by, 'VIEW', NEW.registered_by);
  END IF;
  IF NEW.current_custodian IS NOT NULL THEN
    INSERT IGNORE INTO case_members (case_id, user_id, access_level, added_by)
    VALUES (NEW.case_id, NEW.current_custodian, 'VIEW', NEW.registered_by);
  END IF;
END$$
DELIMITER ;

DROP TRIGGER IF EXISTS trg_evidence_custodian_member;
DELIMITER $$
CREATE TRIGGER trg_evidence_custodian_member
AFTER UPDATE ON evidence
FOR EACH ROW
BEGIN
  IF NEW.current_custodian IS NOT NULL AND NOT (NEW.current_custodian <=> OLD.current_custodian) THEN
    INSERT IGNORE INTO case_members (case_id, user_id, access_level, added_by)
    VALUES (NEW.case_id, NEW.current_custodian, 'VIEW', NEW.current_custodian);
  END IF;
END$$
DELIMITER ;

DROP TRIGGER IF EXISTS trg_custody_members_on_insert;
DELIMITER $$
CREATE TRIGGER trg_custody_members_on_insert
AFTER INSERT ON custody_records
FOR EACH ROW
BEGIN
  DECLARE v_case_id BIGINT UNSIGNED;
  SELECT case_id INTO v_case_id FROM evidence WHERE evidence_id = NEW.evidence_id;
  IF NEW.from_user IS NOT NULL THEN
    INSERT IGNORE INTO case_members (case_id, user_id, access_level, added_by)
    VALUES (v_case_id, NEW.from_user, 'VIEW', NEW.performed_by);
  END IF;
  IF NEW.to_user IS NOT NULL THEN
    INSERT IGNORE INTO case_members (case_id, user_id, access_level, added_by)
    VALUES (v_case_id, NEW.to_user, 'VIEW', NEW.performed_by);
  END IF;
  IF NEW.performed_by IS NOT NULL THEN
    INSERT IGNORE INTO case_members (case_id, user_id, access_level, added_by)
    VALUES (v_case_id, NEW.performed_by, 'VIEW', NEW.performed_by);
  END IF;
END$$
DELIMITER ;

DROP TRIGGER IF EXISTS trg_analysis_member_on_insert;
DELIMITER $$
CREATE TRIGGER trg_analysis_member_on_insert
AFTER INSERT ON analysis_records
FOR EACH ROW
BEGIN
  DECLARE v_case_id BIGINT UNSIGNED;
  SELECT case_id INTO v_case_id FROM evidence WHERE evidence_id = NEW.evidence_id;
  IF NEW.analyst_id IS NOT NULL THEN
    INSERT IGNORE INTO case_members (case_id, user_id, access_level, added_by)
    VALUES (v_case_id, NEW.analyst_id, 'VIEW', NEW.analyst_id);
  END IF;
END$$
DELIMITER ;
