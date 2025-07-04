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

    const success = await sendVulnerabilitiesFoundEmail(userId, websiteId, detectionCount);

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
