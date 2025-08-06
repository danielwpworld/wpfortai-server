import nodemailer from 'nodemailer';
import pool from '../config/db';
import { logToFile } from './debug-logger';

// Define types for database records
interface User {
  uid: string;
  email: string;
  plan?: string;
}

interface Website {
  id: string;
  domain: string;
  uid: string;
}

// Create a SMTP transporter using AWS SES
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'email-smtp.us-east-2.amazonaws.com',
  port: parseInt(process.env.SMTP_PORT || '587'),
  secure: false, // true for 465, false for other ports
  auth: {
    user: process.env.SMTP_USER || '',
    pass: process.env.SMTP_PASS || ''
  }
});

logToFile('Email transporter created with configuration', {
  host: process.env.SMTP_HOST,
  port: process.env.SMTP_PORT,
  user: process.env.SMTP_USER ? '***' : 'not set', // Don't log actual credentials
  secure: false
});

/**
 * Base HTML email template for WPFort emails
 * @param title - Email title
 * @param content - Email body content (HTML)
 * @returns HTML email template
 */
const baseEmailTemplate = (title: string, content: string): string => {
  return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${title}</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap');
    </style>
</head>
<body style="margin: 0; padding: 0; font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #f8f9fa; line-height: 1.6;">
    <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #f8f9fa; min-height: 100vh;">
      <tr>
        <td align="center" style="padding: 40px 20px;">
          <table width="100%" style="max-width: 600px;" cellpadding="0" cellspacing="0">
            <!-- Header -->
            <tr>
              <td style="background-color: #ffffff; padding: 40px 40px 30px; border-radius: 12px 12px 0 0; border-bottom: 1px solid #e9ecef;">
                <table width="100%" cellpadding="0" cellspacing="0">
                  <tr>
                    <td align="center">
                      <img src="https://wpfort.ai/wpfort_logo_newest.png" alt="WPFort" style="height: 32px; margin-bottom: 20px;">
                      <h1 style="color: #1a1a1a; margin: 0; font-size: 24px; font-weight: 600; letter-spacing: -0.02em;">${title}</h1>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>
            <!-- Content -->
            <tr>
              <td style="background-color: #ffffff; padding: 0 40px 40px;">
                ${content}
              </td>
            </tr>
            <!-- Footer -->
            <tr>
              <td style="background-color: #f8f9fa; padding: 32px 40px; text-align: center; border-radius: 0 0 12px 12px; border-top: 1px solid #e9ecef;">
                <p style="color: #6c757d; margin: 0 0 8px 0; font-size: 14px; font-weight: 400;">
                  © 2025 WPFort Security. All rights reserved.
                </p>
                <p style="color: #9ca3af; margin: 0; font-size: 13px;">
                  <a href="https://wpfort.ai" style="color: #4f46e5; text-decoration: none;">wpfort.ai</a> • 
                  Trusted AI-powered protection for WordPress sites
                </p>
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
</html>`;
};

/**
 * Send an email using the configured SMTP transport
 * @param to - Recipient email
 * @param subject - Email subject
 * @param html - Email HTML content
 */
const sendEmail = async (to: string | null, subject: string, html: string): Promise<boolean> => {
  try {
    if (!to) {
      console.error('Cannot send email: recipient email is null or undefined');
      return false;
    }
    
    logToFile('Attempting to send email', { to, subject });
    
    const info = await transporter.sendMail({
      from: '"WPFort Security" <security@wpfort.ai>',
      to,
      subject,
      html,
    });
    
    logToFile('Email sent successfully', { 
      messageId: info.messageId,
      to,
      subject
    });
    console.log(`Email sent successfully to ${to}`);
    return true;
  } catch (error) {
    logToFile('Error sending email', { 
      error: error instanceof Error ? error.message : String(error), 
      stack: error instanceof Error ? error.stack : 'No stack trace',
      to,
      subject
    });
    console.error('Error sending email:', error);
    return false;
  }
};

/**
 * Get user and website details for email sending
 * @param userId - User ID 
 * @param websiteId - Website ID (optional)
 * @returns Object with user and website details
 */
const getUserAndWebsiteDetails = async (
  userId: string,
  websiteId?: string
): Promise<{ user: User | null; website: Website | null }> => {
  try {
    // Get user details
    const userResult = await pool.query(
      'SELECT * FROM users WHERE uid = $1',
      [userId]
    );
    const user = userResult.rows.length > 0 ? userResult.rows[0] : null;

    // Get website details (if websiteId is provided)
    let website = null;
    if (websiteId) {
      const websiteResult = await pool.query(
        'SELECT * FROM websites WHERE id = $1',
        [websiteId]
      );
      website = websiteResult.rows.length > 0 ? websiteResult.rows[0] : null;
    }

    return { user, website };
  } catch (error) {
    console.error('Error fetching user/website details:', error);
    return { user: null, website: null };
  }
};

/**
 * Send onboarding welcome email to new user
 */
const sendWelcomeEmail = async (userId: string): Promise<boolean> => {
  try {
    const { user, website } = await getUserAndWebsiteDetails(userId);
    
    if (!user || !user.email) {
      console.error('User not found or has no email');
      return false;
    }

    const emailSubject = 'Welcome to WPFort.ai – Your WordPress Fortress';
    const emailHtml = baseEmailTemplate(
      'Welcome to WPFort.ai',
      `
      <div style="padding: 20px;">
        <p style="font-size: 18px; margin-bottom: 25px;">Hi ${user.email.split('@')[0]}!</p>
        
        <p style="color: #2c3e50; margin: 0 0 25px 0; line-height: 1.7; font-size: 16px;">
          Welcome to WPFort.ai! 🎉 We're thrilled to have you on board and are looking forward to making your site an absolute Fortress.
        </p>
        
        <div style="background: linear-gradient(to right, #f8f9fa, #e9ecef); border-radius: 10px; padding: 25px; margin: 30px 0; border-left: 5px solid #667eea;">
          <h2 style="color: #4a5568; margin: 0 0 20px 0; font-size: 22px; font-weight: 600;">What You Can Expect</h2>
          
          <div style="margin-bottom: 15px;">
            <p style="margin: 0 0 8px 0; font-weight: 600; color: #2d3748;">✅ One‑Click Clean & Protect</p>
            <p style="margin: 0; color: #4a5568; padding-left: 20px; border-left: 2px solid #cbd5e0;">
              Deploy enterprise-grade, multi-layered protection instantly, no technical know-how needed
            </p>
          </div>
          
          <div style="margin-bottom: 15px;">
            <p style="margin: 0 0 8px 0; font-weight: 600; color: #2d3748;">🔒 24/7 Threat Detection & Response</p>
            <p style="margin: 0; color: #4a5568; padding-left: 20px; border-left: 2px solid #cbd5e0;">
              We continuously monitor your site for malware, brute-force attacks, SQL injections, XSS threats, and more and automatically stop them.
            </p>
          </div>
          
          <div>
            <p style="margin: 0 0 8px 0; font-weight: 600; color: #2d3748;">🤖 AI‑Powered Insights</p>
            <p style="margin: 0; color: #4a5568; padding-left: 20px; border-left: 2px solid #cbd5e0;">
              Get clear, prioritized alerts and tailored security recommendations that work for your specific site.
            </p>
          </div>
        </div>
        
        <div style="background-color: #ebf8ff; border-radius: 10px; padding: 25px; margin: 30px 0;">
          <table width="100%" cellpadding="0" cellspacing="0">
            <tr>
              <td style="vertical-align: middle; padding-right: 10px;">
                <span style="font-size: 28px;">🚀</span>
              </td>
              <td style="vertical-align: middle;">
                <h2 style="color: #2b6cb0; margin: 0; font-size: 22px; font-weight: 600;">What To Do First</h2>
              </td>
            </tr>
          </table>
          
          <ol style="color: #2c5282; padding-left: 25px; margin: 20px 0;">
            <li style="margin-bottom: 12px;">Log in to your dashboard</li>
            <li style="margin-bottom: 12px;">Run your first full scan with one click</li>
            <li style="margin-bottom: 0;">Activate our enterprise grade firewall and Follow our smart suggested actions</li>
          </ol>
          
          <div style="text-align: center; margin: 25px 0 10px 0;">
            <a href="https://www.wpfort.ai/app/dashboard/websites" 
               style="display: inline-block; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: #fff; padding: 16px 32px; border-radius: 50px; text-decoration: none; font-weight: bold; font-size: 18px; box-shadow: 0 4px 10px rgba(102, 126, 234, 0.3); transition: all 0.2s ease;">
              Secure Your Site Now
            </a>
          </div>
        </div>
        
        <div style="margin: 30px 0;">
          <h2 style="color: #4a5568; margin: 0 0 20px 0; font-size: 22px; font-weight: 600;">Why It Matters</h2>
          
          <table width="100%" cellpadding="0" cellspacing="0">
            <tr>
              <td style="width: 20px; vertical-align: middle; padding-right: 10px; padding-bottom: 10px;">
                <span style="color: #667eea; font-weight: bold;">→</span>
              </td>
              <td style="vertical-align: middle; padding-bottom: 10px;">
                <span style="color: #4a5568;">Proactive defense 24/7 – automated malware removal and firewall protection</span>
              </td>
            </tr>
            <tr>
              <td style="width: 20px; vertical-align: middle; padding-right: 10px; padding-bottom: 10px;">
                <span style="color: #667eea; font-weight: bold;">→</span>
              </td>
              <td style="vertical-align: middle; padding-bottom: 10px;">
                <span style="color: #4a5568;">Save time & reduce stress – let WPFort.ai handle threats while you focus on your site</span>
              </td>
            </tr>
            <tr>
              <td style="width: 20px; vertical-align: middle; padding-right: 10px;">
                <span style="color: #667eea; font-weight: bold;">→</span>
              </td>
              <td style="vertical-align: middle;">
                <span style="color: #4a5568;">Scalable security – from single sites to full agency deployments</span>
              </td>
            </tr>
          </table>
        </div>
        
        <div style="background-color: #f7fafc; border: 1px solid #e2e8f0; border-radius: 10px; padding: 25px; margin: 30px 0;">
          <h3 style="color: #4a5568; margin: 0 0 15px 0; font-size: 20px;">Need Help?</h3>
          <p style="color: #4a5568; margin: 0 0 15px 0; line-height: 1.7;">
            Our support team is here to support you every step of the way. Reply to this email anytime or visit our help center.
          </p>
          
          <p style="color: #4a5568; margin: 25px 0 0 0; line-height: 1.7;">
            Thank you for trusting WPFort.ai to protect your online presence. You're now part of a growing community of WordPress professionals who choose speed, simplicity, and smart security.
          </p>
        </div>
        
        <p style="color: #4a5568; margin: 30px 0 5px 0; line-height: 1.7;">
          Cheers,<br>
          <strong>Daniel</strong><br>
          WPFort.ai COO
        </p>
        
        <div style="margin: 30px 0 10px 0; padding: 20px; border-top: 1px dashed #cbd5e0;">
          <p style="color: #718096; font-style: italic; line-height: 1.7;">
            <strong>P.S.</strong> Here's what one user says: <em>"WPFort AI has completely transformed how we manage security… it's like having a security expert constantly monitoring my clients' sites."</em>
          </p>
        </div>
      </div>
    `);
    
    return await sendEmail(user.email, emailSubject, emailHtml);
  } catch (error) {
    console.error('Error sending welcome email:', error);
    return false;
  }
};

/**
 * Send email notification when a new website is added
 */
const sendNewWebsiteEmail = async (userId: string, websiteId: string): Promise<boolean> => {
  try {
    const { user, website } = await getUserAndWebsiteDetails(userId, websiteId);
    
    if (!user || !user.email) {
      console.error('User not found or has no email');
      return false;
    }
    
    if (!website) {
      console.error('Website not found');
      return false;
    }

    const domain = website.domain;
    const siteId = website.id;

    const firstName = user.email.split('@')[0];
    const emailSubject = `${domain} is Now Protected by WPFort.ai 🔐`;
    const emailHtml = baseEmailTemplate(
      `${domain} is Now Protected`,
      `
      <div style="padding: 24px 0 0;">
        <p style="color: #374151; font-size: 16px; margin: 0 0 32px 0; font-weight: 400;">
          Hi ${firstName},
        </p>
        
        <!-- Success Alert Box -->
        <div style="background-color: #f0f9ff; border: 1px solid #bfdbfe; border-radius: 8px; padding: 24px; margin: 0 0 32px 0;">
          <table width="100%" cellpadding="0" cellspacing="0">
            <tr>
              <td style="width: 32px; vertical-align: top; padding-right: 12px;">
                <div style="width: 20px; height: 20px; background-color: #10b981; border-radius: 50%; text-align: center; line-height: 20px;">
                  <span style="color: white; font-size: 12px; font-weight: 600;">✓</span>
                </div>
              </td>
              <td style="vertical-align: top;">
                <h2 style="color: #1e40af; margin: 0 0 8px 0; font-size: 18px; font-weight: 600; line-height: 1.4;">
                  Website Successfully Added: ${domain} is now protected by WPFort.ai
                </h2>
                <p style="color: #1e40af; margin: 0; font-size: 14px; line-height: 1.5;">
                  We've already started monitoring your site for threats and vulnerabilities.
                </p>
              </td>
            </tr>
          </table>
        </div>
        
        <!-- Security Features Section -->
        <div style="background-color: #f9fafb; border: 1px solid #e5e7eb; border-radius: 8px; padding: 24px; margin: 0 0 32px 0;">
          <h3 style="color: #111827; margin: 0 0 16px 0; font-size: 16px; font-weight: 600;">
            AI-Powered Security Monitoring Now Active
          </h3>
          
          <table width="100%" cellpadding="0" cellspacing="0">
            <tr>
              <td style="width: 18px; vertical-align: middle; padding-right: 12px; padding-bottom: 12px;">
                <div style="width: 6px; height: 6px; background-color: #6b7280; border-radius: 50%;"></div>
              </td>
              <td style="vertical-align: middle; padding-bottom: 12px;">
                <span style="color: #374151; font-size: 14px;">Malware, backdoors, and brute-force attack detection</span>
              </td>
            </tr>
            <tr>
              <td style="width: 18px; vertical-align: middle; padding-right: 12px; padding-bottom: 12px;">
                <div style="width: 6px; height: 6px; background-color: #6b7280; border-radius: 50%;"></div>
              </td>
              <td style="vertical-align: middle; padding-bottom: 12px;">
                <span style="color: #374151; font-size: 14px;">Plugin and theme vulnerability scanning</span>
              </td>
            </tr>
            <tr>
              <td style="width: 18px; vertical-align: middle; padding-right: 12px; padding-bottom: 12px;">
                <div style="width: 6px; height: 6px; background-color: #6b7280; border-radius: 50%;"></div>
              </td>
              <td style="vertical-align: middle; padding-bottom: 12px;">
                <span style="color: #374151; font-size: 14px;">Suspicious file changes and unauthorized activity</span>
              </td>
            </tr>
            <tr>
              <td style="width: 18px; vertical-align: middle; padding-right: 12px;">
                <div style="width: 6px; height: 6px; background-color: #6b7280; border-radius: 50%;"></div>
              </td>
              <td style="vertical-align: middle;">
                <span style="color: #374151; font-size: 14px;">SSL monitoring, uptime checks, and more</span>
              </td>
            </tr>
          </table>
          
          <div style="margin-top: 24px; text-align: center;">
            <a href="https://www.wpfort.ai/app/website/${siteId}" 
               style="display: inline-block; background-color: #10b981; color: #ffffff; padding: 12px 24px; border-radius: 6px; text-decoration: none; font-weight: 500; font-size: 14px; border: none; cursor: pointer;">
              View Dashboard
            </a>
          </div>
          
          <p style="color: #6b7280; margin: 16px 0 0 0; font-size: 13px; text-align: center;">
            Access your dashboard to view scan results and manage security settings.
          </p>
        </div>
        
        <!-- Current Plan Section -->
        <div style="background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 24px; margin: 0 0 32px 0;">
          <h3 style="color: #111827; margin: 0 0 8px 0; font-size: 16px; font-weight: 600; text-align: left;">
            You're on the ${user.plan?.toUpperCase() || 'FREE'} Plan
          </h3>
          
          <p style="color: #6b7280; margin: 0 0 20px 0; font-size: 14px; text-align: left; line-height: 1.5;">
            ${user.plan?.toLowerCase() === 'pro' ? 'Enjoy full protection with automatic threat removal and real-time monitoring.' : 'Perfect for personal blogs and hobby sites. Includes daily scans and basic protection.'}
          </p>
          
          <table width="100%" cellpadding="0" cellspacing="0" style="margin: 20px 0;">
            <tr>
              <td style="width: 28px; vertical-align: middle; padding-right: 12px; padding-bottom: 12px;">
                <div style="width: 16px; height: 16px; background-color: #10b981; border-radius: 50%; text-align: center; line-height: 16px;">
                  <span style="color: white; font-size: 10px; font-weight: 600;">✓</span>
                </div>
              </td>
              <td style="vertical-align: middle; padding-bottom: 12px;">
                <span style="color: #374151; font-size: 14px;">Daily security scans</span>
              </td>
            </tr>
            <tr>
              <td style="width: 28px; vertical-align: middle; padding-right: 12px; padding-bottom: 12px;">
                <div style="width: 16px; height: 16px; background-color: #10b981; border-radius: 50%; text-align: center; line-height: 16px;">
                  <span style="color: white; font-size: 10px; font-weight: 600;">✓</span>
                </div>
              </td>
              <td style="vertical-align: middle; padding-bottom: 12px;">
                <span style="color: #374151; font-size: 14px;">6 threat detection engines</span>
              </td>
            </tr>
            <tr>
              <td style="width: 28px; vertical-align: middle; padding-right: 12px; padding-bottom: 12px;">
                <div style="width: 16px; height: 16px; background-color: #10b981; border-radius: 50%; text-align: center; line-height: 16px;">
                  <span style="color: white; font-size: 10px; font-weight: 600;">✓</span>
                </div>
              </td>
              <td style="vertical-align: middle; padding-bottom: 12px;">
                <span style="color: #374151; font-size: 14px;">Automated backups and uptime monitoring</span>
              </td>
            </tr>
            <tr>
              <td style="width: 28px; vertical-align: middle; padding-right: 12px;">
                <div style="width: 16px; height: 16px; background-color: #10b981; border-radius: 50%; text-align: center; line-height: 16px;">
                  <span style="color: white; font-size: 10px; font-weight: 600;">✓</span>
                </div>
              </td>
              <td style="vertical-align: middle;">
                <span style="color: #374151; font-size: 14px;">Brute-force attack protection</span>
              </td>
            </tr>
          </table>
          
${user.plan?.toLowerCase() === 'free' || !user.plan ? `
          <div style="background-color: #fef3c7; border: 1px solid #fbbf24; border-radius: 6px; padding: 16px; margin: 20px 0;">
            <p style="color: #92400e; margin: 0 0 8px 0; font-size: 13px; font-weight: 600;">
              Need automatic threat removal and 24/7 monitoring?
            </p>
            <p style="color: #92400e; margin: 0; font-size: 13px;">
              Upgrade to PRO for one-click malware removal and real-time protection.
            </p>
          </div>
          
          <div style="text-align: center; margin-top: 24px;">
            <a href="https://www.wpfort.ai/#pricing" 
               style="display: inline-block; background-color: #1f9bf0; color: #ffffff; padding: 12px 24px; border-radius: 6px; text-decoration: none; font-weight: 500; font-size: 14px;">
              View Pricing Plans
            </a>
          </div>
` : ''}
        </div>
        
        <p style="color: #6b7280; margin: 0; font-size: 14px; line-height: 1.5;">
          Best regards,<br>
          The WPFort Security Team
        </p>
      </div>
    `);
    
    return await sendEmail(user.email, emailSubject, emailHtml);
  } catch (error) {
    console.error('Error sending new website email:', error);
    return false;
  }
};

/**
 * Send email notification when vulnerabilities are found
 * @param userId - User ID
 * @param websiteId - Website ID
 * @param detectionCount - Total number of vulnerabilities detected (scan detections + application layer vulnerabilities)
 * @returns Whether email was sent successfully
 */
const sendVulnerabilitiesFoundEmail = async (
  userId: string,
  websiteId: string,
  detectionCount: number
): Promise<boolean> => {
  try {
    const { user, website } = await getUserAndWebsiteDetails(userId, websiteId);
    
    if (!user || !user.email) {
      console.error('User not found or has no email');
      return false;
    }
    
    const domain = website?.domain || 'your website';
    const siteId = website?.id || '';
    const severityLevel = detectionCount > 5 ? 'Critical' : detectionCount > 2 ? 'High' : 'Moderate';
    const severityColor = detectionCount > 5 ? '#dc3545' : detectionCount > 2 ? '#ffc107' : '#6c757d';
    
    const content = `
      <div style="padding: 24px 0 0;">
        <p style="color: #374151; font-size: 16px; margin: 0 0 32px 0; font-weight: 400;">
          Hi ${user.email?.split('@')[0] || 'there'},
        </p>
        
        <!-- Alert Box -->
        <div style="background-color: #fef2f2; border: 1px solid #fecaca; border-radius: 8px; padding: 24px; margin: 0 0 32px 0;">
          <table width="100%" cellpadding="0" cellspacing="0">
            <tr>
              <td style="width: 32px; vertical-align: top; padding-right: 12px;">
                <div style="width: 20px; height: 20px; background-color: #dc2626; border-radius: 50%; text-align: center; line-height: 20px;">
                  <span style="color: white; font-size: 12px; font-weight: 600;">!</span>
                </div>
              </td>
              <td style="vertical-align: top;">
                <h2 style="color: #991b1b; margin: 0 0 8px 0; font-size: 18px; font-weight: 600; line-height: 1.4;">
                  Security Alert: ${detectionCount} critical ${detectionCount === 1 ? 'vulnerability' : 'vulnerabilities'} detected on ${domain}
                </h2>
                <p style="color: #7f1d1d; margin: 0; font-size: 14px; line-height: 1.5;">
                  These security issues could expose your site to malware, hackers, or performance problems if left unresolved.
                </p>
              </td>
            </tr>
          </table>
        </div>
        
        <!-- Details Section -->
        <div style="background-color: #f9fafb; border: 1px solid #e5e7eb; border-radius: 8px; padding: 24px; margin: 0 0 32px 0;">
          <h3 style="color: #111827; margin: 0 0 16px 0; font-size: 16px; font-weight: 600;">
            Detected Issues
          </h3>
          
          <table width="100%" cellpadding="0" cellspacing="0">
            <tr>
              <td style="width: 18px; vertical-align: middle; padding-right: 12px; padding-bottom: 12px;">
                <div style="width: 6px; height: 6px; background-color: #6b7280; border-radius: 50%;"></div>
              </td>
              <td style="vertical-align: middle; padding-bottom: 12px;">
                <span style="color: #374151; font-size: 14px;">Vulnerable plugins or themes</span>
              </td>
            </tr>
            <tr>
              <td style="width: 18px; vertical-align: middle; padding-right: 12px; padding-bottom: 12px;">
                <div style="width: 6px; height: 6px; background-color: #6b7280; border-radius: 50%;"></div>
              </td>
              <td style="vertical-align: middle; padding-bottom: 12px;">
                <span style="color: #374151; font-size: 14px;">Configuration weaknesses</span>
              </td>
            </tr>
            <tr>
              <td style="width: 18px; vertical-align: middle; padding-right: 12px;">
                <div style="width: 6px; height: 6px; background-color: #6b7280; border-radius: 50%;"></div>
              </td>
              <td style="vertical-align: middle;">
                <span style="color: #374151; font-size: 14px;">Potential malware or suspicious activity</span>
              </td>
            </tr>
          </table>
          
          <div style="margin-top: 24px; text-align: center;">
            <a href="https://www.wpfort.ai/app/website/${siteId}" 
               style="display: inline-block; background-color: #dc2626; color: #ffffff; padding: 12px 24px; border-radius: 6px; text-decoration: none; font-weight: 500; font-size: 14px; border: none; cursor: pointer;">
              View & Resolve Issues
            </a>
          </div>
          
          <p style="color: #6b7280; margin: 16px 0 0 0; font-size: 13px; text-align: center;">
            Access your dashboard to view detailed information and apply fixes.
          </p>
        </div>
        
${user.plan?.toLowerCase() === 'free' || !user.plan ? `
        <!-- Upgrade Section -->
        <div style="background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 24px; margin: 0 0 32px 0;">
          <h3 style="color: #111827; margin: 0 0 8px 0; font-size: 16px; font-weight: 600; text-align: left;">
            Get Auto-Pilot AI Protection
          </h3>
          
          <p style="color: #6b7280; margin: 0 0 20px 0; font-size: 14px; text-align: left; line-height: 1.5;">
            Activate Sentinel AI Actions for automatic threat resolution while you focus on your business.
          </p>
          
          <table width="100%" cellpadding="0" cellspacing="0" style="margin: 20px 0;">
            <tr>
              <td style="width: 28px; vertical-align: middle; padding-right: 12px; padding-bottom: 12px;">
                <div style="width: 16px; height: 16px; background-color: #10b981; border-radius: 50%; text-align: center; line-height: 16px;">
                  <span style="color: white; font-size: 10px; font-weight: 600;">✓</span>
                </div>
              </td>
              <td style="vertical-align: middle; padding-bottom: 12px;">
                <span style="color: #374151; font-size: 14px;">One-click malware removal</span>
              </td>
            </tr>
            <tr>
              <td style="width: 28px; vertical-align: middle; padding-right: 12px; padding-bottom: 12px;">
                <div style="width: 16px; height: 16px; background-color: #10b981; border-radius: 50%; text-align: center; line-height: 16px;">
                  <span style="color: white; font-size: 10px; font-weight: 600;">✓</span>
                </div>
              </td>
              <td style="vertical-align: middle; padding-bottom: 12px;">
                <span style="color: #374151; font-size: 14px;">Automatic plugin & theme updates</span>
              </td>
            </tr>
            <tr>
              <td style="width: 28px; vertical-align: middle; padding-right: 12px; padding-bottom: 12px;">
                <div style="width: 16px; height: 16px; background-color: #10b981; border-radius: 50%; text-align: center; line-height: 16px;">
                  <span style="color: white; font-size: 10px; font-weight: 600;">✓</span>
                </div>
              </td>
              <td style="vertical-align: middle; padding-bottom: 12px;">
                <span style="color: #374151; font-size: 14px;">Real-time threat blocking</span>
              </td>
            </tr>
            <tr>
              <td style="width: 28px; vertical-align: middle; padding-right: 12px;">
                <div style="width: 16px; height: 16px; background-color: #10b981; border-radius: 50%; text-align: center; line-height: 16px;">
                  <span style="color: white; font-size: 10px; font-weight: 600;">✓</span>
                </div>
              </td>
              <td style="vertical-align: middle;">
                <span style="color: #374151; font-size: 14px;">Proactive security monitoring</span>
              </td>
            </tr>
          </table>
          
          <div style="text-align: center; margin-top: 24px;">
            <a href="https://www.wpfort.ai/#pricing" 
               style="display: inline-block; background-color: #1f9bf0; color: #ffffff; padding: 12px 24px; border-radius: 6px; text-decoration: none; font-weight: 500; font-size: 14px;">
              View Pricing Plans
            </a>
          </div>
        </div>
` : ''}
        
        <p style="color: #6b7280; margin: 0; font-size: 14px; line-height: 1.5;">
          Best regards,<br>
          The WPFort Security Team
        </p>
      </div>
    `;
    
    logToFile('Preparing to send vulnerabilities email', {
      to: user.email,
      domain,
      severityLevel,
      detectionCount
    });
    
    const emailSubject = `⚠️ WPFort Found ${detectionCount} ${detectionCount === 1 ? 'Vulnerability' : 'Vulnerabilities'} on Your Site – Take Action Now`;
    const html = baseEmailTemplate('Security Alert: Vulnerabilities Detected', content);
    
    logToFile('Sending vulnerabilities email with subject', { emailSubject });
    
    // Adding a short delay before sending (AWS SES might have rate limits)
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    const result = await sendEmail(user.email, emailSubject, html);
    logToFile('Vulnerabilities email send result', { result });
    return result;
  } catch (error) {
    console.error('Error sending vulnerabilities email:', error);
    return false;
  }
};

export {
  sendWelcomeEmail,
  sendNewWebsiteEmail,
  sendVulnerabilitiesFoundEmail
};
