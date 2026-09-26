-- Add examiner_timezone to evidence table for external evidentiary timezone assertions
ALTER TABLE evidence ADD COLUMN examiner_timezone TEXT;
