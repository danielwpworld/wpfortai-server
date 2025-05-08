import * as crypto from 'crypto';
import pool from '../config/db';

export interface WebhookSecret {
  id: number;
  website_id: number;
  secret_key: string;
  created_at: Date;
}

export class WebhookSecrets {
  // Constants for secret rotation
  private static readonly ROTATION_WINDOW_HOURS = 24; // How long old secrets remain valid
  private static readonly AUTO_ROTATION_DAYS = 90; // Auto-rotate secrets after 90 days

  /**
   * Generate a new webhook secret
   */
  static generateSecret(): string {
    return crypto.randomBytes(32).toString('hex');
  }

  /**
   * Get webhook secret for a website
   */
  static async getWebhookSecret(websiteId: string): Promise<{ currentSecret: string; oldSecret?: string } | null> {
    const result = await pool.query(
      `SELECT 
        secret_key, 
        old_secret_key, 
        rotation_started_at,
        last_used_at
       FROM webhook_secrets 
       WHERE website_id = $1`,
      [websiteId]
    );

    if (!result.rows[0]) return null;

    // Update last_used timestamp
    await pool.query(
      'UPDATE webhook_secrets SET last_used_at = CURRENT_TIMESTAMP WHERE website_id = $1',
      [websiteId]
    );

    const { secret_key, old_secret_key, rotation_started_at } = result.rows[0];

    // Check if we're in rotation window
    if (old_secret_key && rotation_started_at) {
      const rotationEndTime = new Date(rotation_started_at);
      rotationEndTime.setHours(rotationEndTime.getHours() + this.ROTATION_WINDOW_HOURS);

      if (new Date() < rotationEndTime) {
        // Still in rotation window, return both secrets
        return {
          currentSecret: secret_key,
          oldSecret: old_secret_key
        };
      }

      // Rotation window expired, clear old secret
      await pool.query(
        'UPDATE webhook_secrets SET old_secret_key = NULL, rotation_started_at = NULL WHERE website_id = $1',
        [websiteId]
      );
    }

    return { currentSecret: secret_key };
  }

  /**
   * Create or update webhook secret for a website
   */
  static async createOrUpdateSecret(websiteId: string): Promise<string> {
    const newSecret = this.generateSecret();
    
    // Get existing secret if any
    const result = await pool.query(
      'SELECT secret_key FROM webhook_secrets WHERE website_id = $1',
      [websiteId]
    );

    if (result.rows[0]) {
      // Update with rotation
      await pool.query(
        `UPDATE webhook_secrets 
         SET secret_key = $2,
             old_secret_key = secret_key,
             rotation_started_at = CURRENT_TIMESTAMP
         WHERE website_id = $1`,
        [websiteId, newSecret]
      );
    } else {
      // First time creation
      await pool.query(
        `INSERT INTO webhook_secrets (website_id, secret_key)
         VALUES ($1, $2)`,
        [websiteId, newSecret]
      );
    }

    return newSecret;
  }

  /**
   * Delete webhook secret for a website
   */
  static async deleteWebhookSecret(websiteId: string): Promise<void> {
    await pool.query(
      'DELETE FROM webhook_secrets WHERE website_id = $1',
      [websiteId]
    );
  }

  /**
   * Check for secrets that need rotation and rotate them
   */
  static async checkAndRotateSecrets(): Promise<void> {
    const result = await pool.query(
      `SELECT website_id 
       FROM webhook_secrets 
       WHERE last_used_at < CURRENT_TIMESTAMP - INTERVAL '${this.AUTO_ROTATION_DAYS} days'
       AND old_secret_key IS NULL`,
    );

    for (const row of result.rows) {
      await this.createOrUpdateSecret(row.website_id);
    }
  }
}
