require('dotenv').config({ path: '.env.local' });
const { Pool } = require('pg');

// Create connection pool with SSL settings for Neon Postgres
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

async function getUserWebsites() {
  try {
    console.log('Connecting to database...');
    
    // Get user details
    const userResult = await pool.query(
      'SELECT uid, email FROM users WHERE uid = $1',
      ['RDYjCKqzxmRtNLxkdlCfpHuLgHw2']
    );
    
    if (userResult.rows.length === 0) {
      console.log('User not found');
      process.exit(1);
    }
    
    console.log('User found:', userResult.rows[0]);
    
    // Get websites for this user
    const websiteResult = await pool.query(
      'SELECT id, domain FROM websites WHERE uid = $1',
      ['RDYjCKqzxmRtNLxkdlCfpHuLgHw2']
    );
    
    console.log('Websites found:', websiteResult.rows.length);
    console.log(websiteResult.rows);
    
    await pool.end();
  } catch (error) {
    console.error('Error querying database:', error);
  }
}

getUserWebsites();
