-- Migration to change detection_type column in scan_detections from text to text[]
-- This will convert existing single values to arrays with one element

-- First, create a backup of the scan_detections table just in case
CREATE TABLE scan_detections_backup AS SELECT * FROM scan_detections;

-- Add a comment to indicate a backup was created
COMMENT ON TABLE scan_detections_backup IS 'Backup of scan_detections table before changing detection_type to array type';

-- Check if there are any NULL values in detection_type and set them to empty arrays
UPDATE scan_detections 
SET detection_type = 'unknown' 
WHERE detection_type IS NULL;

-- Alter the column type to text array, converting existing values to single-element arrays
ALTER TABLE scan_detections 
ALTER COLUMN detection_type TYPE text[] 
USING array[detection_type];

-- Add a comment to the column to document the change
COMMENT ON COLUMN scan_detections.detection_type IS 'Array of detection types for the file (e.g., ["malware", "backdoor"])';

-- Create an index on the detection_type column to improve query performance
CREATE INDEX idx_scan_detections_detection_type ON scan_detections USING GIN (detection_type);

-- Verify the change (this is informational and doesn't affect the schema)
-- SELECT id, file_path, detection_type FROM scan_detections LIMIT 10;
