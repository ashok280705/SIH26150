-- Down migration for Phase 1 Core Metadata Schema

DROP TABLE IF EXISTS source_regions;
DROP TABLE IF EXISTS artifacts;
DROP TABLE IF EXISTS provenance;
DROP TABLE IF EXISTS hashes;
DROP TABLE IF EXISTS source_safety_reports;
DROP TABLE IF EXISTS chain_of_custody;
DROP TABLE IF EXISTS evidence;
DROP TABLE IF EXISTS acquisitions;
DROP TABLE IF EXISTS validation_states;
DROP TABLE IF EXISTS capability_stages;
DROP TABLE IF EXISTS cases;
