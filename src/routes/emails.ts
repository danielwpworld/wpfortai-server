import { Router } from 'express';
import { 
  sendWelcomeEmail, 
  sendNewWebsiteEmail, 
  sendVulnerabilitiesFoundEmail 
} from '../services/email';
import pool from '../config/db';

const router = Router();

/**
 * @route POST /api/emails/welcome
 * @desc Send welcome email to a new user
 */
router.post('/welcome', async (req, res) => {
  try {
    const { userId } = req.body;

    if (!userId) {
      return res.status(400).json({ 
        success: false, 
        message: 'User ID is required' 
      });
    }

    // Verify user exists
    const userResult = await pool.query(
      'SELECT * FROM users WHERE uid = $1',
      [userId]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ 
        success: false, 
        message: 'User not found' 
      });
    }
    
    const user = userResult.rows[0];

    const success = await sendWelcomeEmail(userId);

    if (success) {
      return res.status(200).json({ 
        success: true, 
        message: 'Welcome email sent successfully' 
      });
    } else {
      return res.status(500).json({ 
        success: false, 
        message: 'Failed to send welcome email' 
      });
    }
  } catch (error) {
    console.error('Error sending welcome email:', error);
    return res.status(500).json({ 
      success: false, 
      message: 'Error sending welcome email', 
      error: (error as Error).message 
    });
  }
});

/**
 * @route POST /api/emails/new-website
 * @desc Send email notification when a new website is added
 */
router.post('/new-website', async (req, res) => {
  try {
    const { userId, websiteId } = req.body;

    if (!userId || !websiteId) {
      return res.status(400).json({ 
        success: false, 
        message: 'User ID and Website ID are required' 
      });
    }

    // Verify user and website exist
    const userResult = await pool.query(
      'SELECT * FROM users WHERE uid = $1',
      [userId]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ 
        success: false, 
        message: 'User not found' 
      });
    }
    
    const user = userResult.rows[0];

    const websiteResult = await pool.query(
      'SELECT * FROM websites WHERE id = $1',
      [websiteId]
    );

    if (websiteResult.rows.length === 0) {
      return res.status(404).json({ 
        success: false, 
        message: 'Website not found' 
      });
    }
    
    const website = websiteResult.rows[0];

    const success = await sendNewWebsiteEmail(userId, websiteId);

    if (success) {
      return res.status(200).json({ 
        success: true, 
        message: 'New website email sent successfully' 
      });
    } else {
      return res.status(500).json({ 
        success: false, 
        message: 'Failed to send new website email' 
      });
    }
  } catch (error) {
    console.error('Error sending new website email:', error);
    return res.status(500).json({ 
      success: false, 
      message: 'Error sending new website email', 
      error: (error as Error).message 
    });
  }
});

/**
 * @route POST /api/emails/vulnerabilities-found
 * @desc Send email notification when vulnerabilities are found
 */
router.post('/vulnerabilities-found', async (req, res) => {
  try {
    const { userId, websiteId, detectionCount } = req.body;

    if (!userId || !websiteId || detectionCount === undefined) {
      return res.status(400).json({ 
        success: false, 
        message: 'User ID, Website ID, and detection count are required' 
      });
    }

    // Verify user and website exist
    const userResult = await pool.query(
      'SELECT * FROM users WHERE uid = $1',
      [userId]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ 
        success: false, 
        message: 'User not found' 
      });
    }
    
    const user = userResult.rows[0];

    const websiteResult = await pool.query(
      'SELECT * FROM websites WHERE id = $1',
      [websiteId]
    );

    if (websiteResult.rows.length === 0) {
      return res.status(404).json({ 
        success: false, 
        message: 'Website not found' 
      });
    }
    
    const website = websiteResult.rows[0];

    // Fetch application layer data to compute vulnerable plugins count
    const websiteDataResult = await pool.query(
      'SELECT application_layer FROM website_data WHERE website_id = $1',
      [websiteId]
    );

    let vulnerablePlugins = 0;
    if (websiteDataResult.rows.length > 0 && websiteDataResult.rows[0].application_layer) {
      const appLayer = websiteDataResult.rows[0].application_layer as any;
      const plugins = appLayer?.plugins;
      // Prefer maintained counter if present; otherwise derive from items
      if (plugins && typeof plugins.vulnerable !== 'undefined') {
        vulnerablePlugins = Number(plugins.vulnerable) || 0;
      } else if (plugins && Array.isArray(plugins.items)) {
        vulnerablePlugins = plugins.items.filter((p: any) => Array.isArray(p?.vulnerabilities) && p.vulnerabilities.length > 0).length;
      }
    }

    // Determine latest website scan and count ACTIVE detections only
    let lastScanActiveDetections = 0;
    const lastScanRes = await pool.query(
      `SELECT scan_id
       FROM website_scans
       WHERE website_id = $1
       ORDER BY completed_at DESC NULLS LAST, started_at DESC NULLS LAST
       LIMIT 1`,
      [websiteId]
    );

    if (lastScanRes.rows.length > 0 && lastScanRes.rows[0].scan_id) {
      const lastScanId = lastScanRes.rows[0].scan_id as string;
      const activeCountRes = await pool.query(
        `SELECT COUNT(*)::int AS count
         FROM scan_detections
         WHERE scan_id = $1 AND status = 'active'`,
        [lastScanId]
      );
      lastScanActiveDetections = activeCountRes.rows[0]?.count || 0;
    }

    // Final total: ACTIVE detections from last scan + vulnerable plugins
    const totalVulnerabilities = Number(lastScanActiveDetections) + Number(vulnerablePlugins);

    const success = await sendVulnerabilitiesFoundEmail(userId, websiteId, totalVulnerabilities);

    if (success) {
      return res.status(200).json({ 
        success: true, 
        message: 'Vulnerabilities found email sent successfully' 
      });
    } else {
      return res.status(500).json({ 
        success: false, 
        message: 'Failed to send vulnerabilities found email' 
      });
    }
  } catch (error) {
    console.error('Error sending vulnerabilities found email:', error);
    return res.status(500).json({ 
      success: false, 
      message: 'Error sending vulnerabilities found email', 
      error: (error as Error).message 
    });
  }
});

export default router;
