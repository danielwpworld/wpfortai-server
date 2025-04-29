-- Migration: Create whitelisted_detections table

CREATE TABLE IF NOT EXISTS whitelisted_detections (
    id SERIAL PRIMARY KEY,
    website_id UUID NOT NULL REFERENCES websites(id) ON DELETE CASCADE,
    scan_detection_id INTEGER REFERENCES scan_detections(id) ON DELETE CASCADE,
    file_path TEXT NOT NULL,
    file_hash TEXT,
    file_size BIGINT,
    detection_type TEXT[] NOT NULL,
    reason TEXT,
    whitelisted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (website_id, file_path)
);
