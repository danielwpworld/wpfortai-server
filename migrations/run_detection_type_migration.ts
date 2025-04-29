import { Pool } from 'pg';
import * as fs from 'fs';
import * as path from 'path';
import dotenv from 'dotenv';
import { logger } from '../src/services/logger';

// Load environment variables
dotenv.config();

// Log the database URL (without sensitive info)
const dbUrl = process.env.DATABASE_URL || '';
const maskedUrl = dbUrl.replace(/:\/\/[^@]+@/, '://****@');
console.log(`Using database: ${maskedUrl}`);

// Create a connection pool with direct database URL
const DATABASE_URL = 'postgresql://neondb_owner:npg_mwildA5jUbS2@ep-fancy-tooth-a28w5trr-pooler.eu-central-1.aws.neon.tech/neondb?sslmode=require';

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

async function runMigration() {
  const client = await pool.connect();
  
  try {
    console.log('Starting migration: Altering detection_type column to array type');
    
    // Begin transaction
    await client.query('BEGIN');
    
    // Read the migration SQL file
    const migrationPath = path.join(__dirname, 'alter_detection_type_to_array.sql');
    const migrationSQL = fs.readFileSync(migrationPath, 'utf8');
    
    // Execute the entire SQL script at once
    await client.query(migrationSQL);
    
    console.log('Executed migration SQL script');
    
    // Commit transaction
    await client.query('COMMIT');
    
    console.log('Migration completed successfully');
    
    // Verify the change
    const result = await client.query('SELECT id, file_path, detection_type FROM scan_detections LIMIT 5');
    console.log('Sample data after migration:');
    console.table(result.rows);
    
  } catch (error) {
    // Rollback transaction on error
    await client.query('ROLLBACK');
    console.error('Migration failed:', error);
    throw error;
  } finally {
    // Release the client back to the pool
    client.release();
    await pool.end();
  }
}

// Run the migration
runMigration().catch(err => {
  console.error('Migration script error:', err);
  process.exit(1);
});
