-- Link clearance units under SAS and Dean parent offices.
ALTER TABLE offices
    ADD COLUMN parent_office_id INT UNSIGNED NULL AFTER sequence_no,
    ADD CONSTRAINT fk_office_parent FOREIGN KEY (parent_office_id) REFERENCES offices(id);

UPDATE offices child
INNER JOIN offices parent ON parent.code = 'SAS'
SET child.parent_office_id = parent.id
WHERE child.code IN ('SSC', 'DORM', 'ACCT', 'SOA')
  AND child.parent_office_id IS NULL;

UPDATE offices child
INNER JOIN offices parent ON parent.code = 'DEAN'
SET child.parent_office_id = parent.id
WHERE child.code = 'LIB'
  AND child.parent_office_id IS NULL;
