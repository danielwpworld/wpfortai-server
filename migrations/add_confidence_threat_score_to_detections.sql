-- Migration: Add confidence and threat_score to quarantined_detections, deleted_detections, whitelisted_detections

ALTER TABLE quarantined_detections
    ADD COLUMN confidence NUMERIC,
    ADD COLUMN threat_score NUMERIC;

ALTER TABLE deleted_detections
    ADD COLUMN confidence NUMERIC,
    ADD COLUMN threat_score NUMERIC;

ALTER TABLE whitelisted_detections
    ADD COLUMN confidence NUMERIC,
    ADD COLUMN threat_score NUMERIC;
