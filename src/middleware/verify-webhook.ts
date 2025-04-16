import { Request, Response, NextFunction } from 'express';
import * as crypto from 'crypto';

const WEBHOOK_TOLERANCE_SECONDS = 300; // 5 minutes

interface WebhookHeaders {
  'x-wpfort-signature': string;
  'x-wpfort-timestamp': string;
}

export function verifyWebhook(websiteSecret: string) {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      const signature = req.header('x-wpfort-signature');
      const timestamp = req.header('x-wpfort-timestamp');

      if (!signature || !timestamp) {
        return res.status(401).json({ error: 'Missing required headers' });
      }

      // Verify timestamp is recent
      const timestampNum = parseInt(timestamp, 10);
      const now = Math.floor(Date.now() / 1000);
      if (Math.abs(now - timestampNum) > WEBHOOK_TOLERANCE_SECONDS) {
        return res.status(401).json({ error: 'Request timestamp too old' });
      }

      // Create signature
      const payload = JSON.stringify(req.body);
      const signatureData = `${timestamp}.${payload}`;
      const expectedSignature = crypto
        .createHmac('sha256', websiteSecret)
        .update(signatureData)
        .digest('hex');

      // Compare signatures
      if (signature !== expectedSignature) {
        return res.status(401).json({ error: 'Invalid signature' });
      }

      next();
    } catch (error) {
      console.error('Error verifying webhook:', error);
      res.status(500).json({ error: 'Error verifying webhook' });
    }
  };
}
