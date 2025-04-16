import * as crypto from 'crypto';
import pool from '../config/db';

export interface WebhookSecret {
  id: number;
  website_id: number;
  secret_key: string;
  created_at: Date;
}

export class WebhookSecrets {
  /**
   * Generate a new webhook secret for a website
   */
  static generateSecret(): string {
    return crypto.randomBytes(32).toString('hex');
  }

  /**
   * Get webhook secret for a website
   */
  static async getWebhookSecret(websiteId: number): Promise<string | null> {
    const result = await pool.query(
      'SELECT secret_key FROM webhook_secrets WHERE website_id = $1',
      [websiteId]
    );
    return result.rows[0]?.secret_key || null;
  }

  /**
   * Create or update webhook secret for a website
   */
  static async createOrUpdateSecret(websiteId: number): Promise<string> {
    const secret = this.generateSecret();
    
    await pool.query(
      `INSERT INTO webhook_secrets (website_id, secret_key)
       VALUES ($1, $2)
       ON CONFLICT (website_id) 
       DO UPDATE SET secret_key = $2`,
      [websiteId, secret]
    );

    return secret;
  }

  /**
   * Delete webhook secret for a website
   */
  static async deleteWebhookSecret(websiteId: number): Promise<void> {
    await pool.query(
      'DELETE FROM webhook_secrets WHERE website_id = $1',
      [websiteId]
    );
  }
}
