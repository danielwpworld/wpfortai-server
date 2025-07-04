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
</head>
<body style="margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f5f5f5;">
    <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #f5f5f5;">
      <tr>
        <td align="center" style="padding: 20px;">
          <table width="600" cellpadding="0" cellspacing="0" style="background-color: #ffffff; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
            <tr>
              <td style="padding: 30px 40px; text-align: center; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); border-radius: 8px 8px 0 0;">
                <img src="https://www.wpfort.ai/wpfort-logo-dark.png" alt="WPFort" style="height: 40px; margin-bottom: 15px;">
                <h1 style="color: #ffffff; margin: 0; font-size: 28px; font-weight: 600;">${title}</h1>
              </td>
            </tr>
            <tr>
              <td style="padding: 30px 40px;">
                ${content}
              </td>
            </tr>
            <tr>
              <td style="padding: 20px 40px; background-color: #2c3e50; text-align: center; border-radius: 0 0 8px 8px;">
                <p style="color: #ffffff; margin: 0; font-size: 14px;"> 2025 WPFort Security. All rights reserved.</p>
                <p style="color: #bdc3c7; margin: 5px 0 0 0; font-size: 12px;">
                  <a href="https://wpfort.ai" style="color: #bdc3c7; text-decoration: underline;">Visit wpfort.ai</a> | 
                  Trusted AI-powered protection for your WordPress sites
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
          <h2 style="color: #2b6cb0; margin: 0 0 20px 0; font-size: 22px; font-weight: 600; display: flex; align-items: center;">
            <span style="font-size: 28px; margin-right: 10px;">🚀</span> What To Do First
          </h2>
          
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
          
          <ul style="color: #4a5568; padding-left: 0; list-style-type: none;">
            <li style="margin-bottom: 10px; display: flex; align-items: center;">
              <span style="color: #667eea; font-weight: bold; margin-right: 10px;">→</span>
              <span>Proactive defense 24/7 – automated malware removal and firewall protection</span>
            </li>
            <li style="margin-bottom: 10px; display: flex; align-items: center;">
              <span style="color: #667eea; font-weight: bold; margin-right: 10px;">→</span>
              <span>Save time & reduce stress – let WPFort.ai handle threats while you focus on your site</span>
            </li>
            <li style="margin-bottom: 10px; display: flex; align-items: center;">
              <span style="color: #667eea; font-weight: bold; margin-right: 10px;">→</span>
              <span>Scalable security – from single sites to full agency deployments</span>
            </li>
          </ul>
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
      <div style="padding: 20px;">
        <p style="font-size: 18px; margin-bottom: 25px;">Hi ${firstName},</p>
        
        <p style="color: #2c3e50; margin: 0 0 25px 0; line-height: 1.7; font-size: 16px;">
          Great news! Your new WordPress site <strong style="color: #4a5568;">${domain}</strong> has been successfully added to your WPFort.ai dashboard!
        </p>
        
        <div style="background: linear-gradient(to right, #f0f9ff, #e6f7ff); border-radius: 12px; padding: 25px; margin: 30px 0; border-left: 5px solid #38b2ac;">
          <h2 style="color: #2c5282; margin: 0 0 20px 0; font-size: 20px; font-weight: 600; display: flex; align-items: center;">
            <span style="font-size: 24px; margin-right: 10px;">🔎</span> We've already run the first AI-powered scan and started monitoring for:
          </h2>
          
          <ul style="color: #2d3748; padding-left: 15px; margin: 15px 0;">
            <li style="margin-bottom: 8px; position: relative; padding-left: 5px;">
              <span style="font-weight: 500;">Malware, backdoors, and brute-force attacks</span>
            </li>
            <li style="margin-bottom: 8px; position: relative; padding-left: 5px;">
              <span style="font-weight: 500;">Plugin/theme vulnerabilities</span>
            </li>
            <li style="margin-bottom: 8px; position: relative; padding-left: 5px;">
              <span style="font-weight: 500;">Suspicious file changes and unauthorized activity</span>
            </li>
            <li style="margin-bottom: 0; position: relative; padding-left: 5px;">
              <span style="font-weight: 500;">SSL issues, uptime status, and more</span>
            </li>
          </ul>
        </div>
        
        <div style="background-color: #f7fafc; border: 1px solid #edf2f7; border-radius: 12px; padding: 25px; margin: 30px 0;">
          <h3 style="color: #3182ce; margin: 0 0 15px 0; font-size: 20px; font-weight: 600; text-align: center;">You're currently on the <span style="background-color: #5a67d8; color: white; padding: 2px 8px; border-radius: 4px; font-weight: 700;">FREE</span> plan</h3>
          
          <p style="color: #4a5568; margin: 15px 0; line-height: 1.6; text-align: center;">
            It's perfect for personal blogs or hobby sites and includes:
          </p>
          
          <div style="display: flex; flex-direction: column; gap: 10px; margin: 20px 0;">
            <div style="display: flex; align-items: center;">
              <span style="color: #38a169; font-weight: bold; margin-right: 10px; font-size: 18px;">✅</span>
              <span style="color: #2d3748;">Daily scans</span>
            </div>
            <div style="display: flex; align-items: center;">
              <span style="color: #38a169; font-weight: bold; margin-right: 10px; font-size: 18px;">✅</span>
              <span style="color: #2d3748;">6 detection engines</span>
            </div>
            <div style="display: flex; align-items: center;">
              <span style="color: #38a169; font-weight: bold; margin-right: 10px; font-size: 18px;">✅</span>
              <span style="color: #2d3748;">Backups, uptime checks, brute-force protection, and more</span>
            </div>
          </div>
          
          <div style="background-color: #fefcbf; border-radius: 8px; padding: 20px; margin: 25px 0 20px 0; border: 1px solid #f6e05e;">
            <p style="color: #744210; margin: 0; line-height: 1.6;">
              <strong>Want twice-daily scanning, one-click malware removal, smart Reports, a full AI Security team around-the-clock and auto-updates?</strong>
            </p>
            <p style="color: #744210; margin: 10px 0 0 0; font-weight: 600;">
              👉 Upgrade to PRO – just $29/month or $199/year for up to 3 sites.
            </p>
          </div>
          
          <div style="text-align: center; margin: 25px 0 10px 0;">
            <a href="https://www.wpfort.ai/#pricing" 
               style="display: inline-block; background: linear-gradient(135deg, #f6ad55 0%, #ed8936 100%); color: #fff; padding: 14px 28px; border-radius: 50px; text-decoration: none; font-weight: bold; font-size: 16px; box-shadow: 0 4px 6px rgba(237, 137, 54, 0.25); transition: all 0.2s ease;">
              Upgrade to PRO
            </a>
          </div>
        </div>
        
        <div style="background-color: #ebf8ff; border-radius: 12px; padding: 25px; margin: 30px 0;">
          <h2 style="color: #2b6cb0; margin: 0 0 20px 0; font-size: 22px; font-weight: 600; display: flex; align-items: center;">
            <span style="font-size: 24px; margin-right: 10px;">🛡️</span> Next Steps
          </h2>
          
          <ul style="color: #2c5282; padding-left: 5px; list-style-type: none; margin: 20px 0;">
            <li style="margin-bottom: 12px; display: flex;">
              <span style="color: #4299e1; font-weight: bold; margin-right: 10px;">1.</span>
              <span>Visit your dashboard to review your site's first protection report</span>
            </li>
            <li style="margin-bottom: 12px; display: flex;">
              <span style="color: #4299e1; font-weight: bold; margin-right: 10px;">2.</span>
              <span>Enable our Smart Firewall to boost your security scans</span>
            </li>
            <li style="margin-bottom: 12px; display: flex;">
              <span style="color: #4299e1; font-weight: bold; margin-right: 10px;">3.</span>
              <span>Explore upgrade options if your site is infected, handles sensitive data or customers or if you want total peace of mind while WPFort takes care of it all.</span>
            </li>
          </ul>
          
          <div style="text-align: center; margin: 25px 0 10px 0;">
            <a href="https://www.wpfort.ai/app/website/${siteId}" 
               style="display: inline-block; background: linear-gradient(135deg, #4299e1 0%, #3182ce 100%); color: #fff; padding: 14px 28px; border-radius: 50px; text-decoration: none; font-weight: bold; font-size: 16px; box-shadow: 0 4px 6px rgba(66, 153, 225, 0.3); transition: all 0.2s ease;">
              View Your Dashboard
            </a>
          </div>
        </div>
        
        <p style="color: #4a5568; margin: 20px 0; line-height: 1.7;">
          Have questions? Our support team is always here to help.
        </p>
        
        <p style="color: #4a5568; margin: 30px 0 5px 0; line-height: 1.7;">
          Stay safe,<br>
          – The WPFort.ai Team
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
 * @param detectionCount - Number of vulnerabilities detected
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
      <div style="padding: 10px 0;">
        <p style="color: #2d3748; font-size: 18px; margin-bottom: 20px;">
          Hi ${user.email?.split('@')[0] || 'there'},
        </p>
        
        <div style="background-color: #FEF2F2; border-left: 4px solid #DC2626; padding: 20px; border-radius: 8px; margin: 25px 0;">
          <h2 style="color: #991B1B; margin: 0 0 15px 0; font-size: 22px;">
            <span style="font-size: 24px; margin-right: 10px; display: inline-block; vertical-align: middle;">⚠️</span> 
            Alert: WPFort.ai just detected 
            <span style="font-weight: 700;">${detectionCount} critical ${detectionCount === 1 ? 'vulnerability' : 'vulnerabilities'}</span>
            on your site 
            <span style="color: #2563EB;">${domain}</span>
          </h2>
          
          <p style="color: #7F1D1D; margin: 15px 0; line-height: 1.7;">
            These security issues could expose your site to malware, hackers, or performance problems if left unresolved.
          </p>
        </div>
        
        <div style="background-color: #F7FAFC; border: 1px solid #E2E8F0; padding: 20px; border-radius: 8px; margin: 25px 0;">
          <h3 style="color: #2B6CB0; display: flex; align-items: center; margin: 0 0 15px 0; font-size: 18px;">
            <span style="font-size: 20px; margin-right: 10px;">🛡️</span> These include:
          </h3>
          
          <ul style="color: #4A5568; padding-left: 15px; margin: 15px 0; line-height: 1.8;">
            <li style="margin-bottom: 10px;">Vulnerable plugins or themes</li>
            <li style="margin-bottom: 10px;">Configuration weaknesses</li>
            <li style="margin-bottom: 10px;">Potential malware or suspicious activity</li>
          </ul>
          
          <div style="text-align: center; margin: 25px 0 10px 0;">
            <a href="https://www.wpfort.ai/app/website/${siteId}" 
               style="display: inline-block; background: linear-gradient(135deg, #EF4444 0%, #B91C1C 100%); color: #fff; padding: 14px 28px; border-radius: 50px; text-decoration: none; font-weight: bold; font-size: 16px; box-shadow: 0 4px 6px rgba(239, 68, 68, 0.25); transition: all 0.2s ease;">
              🔍 View & Resolve Issues Now »
            </a>
          </div>
          
          <p style="color: #4A5568; margin: 15px 0; font-size: 14px; text-align: center;">
            You can view the full list and apply the required fixes through WPFort.
          </p>
        </div>
        
        <div style="border: 1px solid #E2E8F0; border-radius: 8px; padding: 25px; margin: 30px 0; background: linear-gradient(to bottom, #F7FAFC 0%, #EDF2F7 100%);">
          <h3 style="color: #2D3748; margin: 0 0 20px 0; font-size: 18px; text-align: center;">
            Want these threats all handled automatically while you sleep?
          </h3>
          
          <p style="color: #4A5568; margin: 15px 0; line-height: 1.6; font-weight: 500; text-align: center;">
            Upgrade to PRO or BUSINESS and let WPFort AI AutoPilot instantly:
          </p>
          
          <div style="display: flex; flex-direction: column; gap: 10px; margin: 20px 0;">
            <div style="display: flex; align-items: center;">
              <span style="color: #38a169; font-weight: bold; margin-right: 10px; font-size: 18px;">✅</span>
              <span style="color: #2d3748;">Remove malware in one click</span>
            </div>
            <div style="display: flex; align-items: center;">
              <span style="color: #38a169; font-weight: bold; margin-right: 10px; font-size: 18px;">✅</span>
              <span style="color: #2d3748;">Auto-update plugins/themes</span>
            </div>
            <div style="display: flex; align-items: center;">
              <span style="color: #38a169; font-weight: bold; margin-right: 10px; font-size: 18px;">✅</span>
              <span style="color: #2d3748;">Block new threats in real-time</span>
            </div>
            <div style="display: flex; align-items: center;">
              <span style="color: #38a169; font-weight: bold; margin-right: 10px; font-size: 18px;">✅</span>
              <span style="color: #2d3748;">Schedule proactive scans</span>
            </div>
          </div>
          
          <p style="color: #4A5568; margin: 25px 0 20px; line-height: 1.7; text-align: center; font-weight: 500;">
            <span style="color: #2B6CB0; font-size: 18px;">🧠</span> Focus on growing your site and business, we'll handle the rest.
          </p>
          
          <div style="text-align: center; margin: 25px 0 10px 0;">
            <a href="https://www.wpfort.ai/#pricing" 
               style="display: inline-block; background: linear-gradient(135deg, #4299e1 0%, #3182ce 100%); color: #fff; padding: 14px 28px; border-radius: 50px; text-decoration: none; font-weight: bold; font-size: 16px; box-shadow: 0 4px 6px rgba(66, 153, 225, 0.3); transition: all 0.2s ease;">
              👉 See Plans & Pricing »
            </a>
          </div>
        </div>
        
        <p style="color: #4a5568; margin: 30px 0 5px 0; line-height: 1.7;">
          Stay protected,<br>
          – The WPFort.ai Team
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
