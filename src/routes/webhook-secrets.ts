import { Router } from 'express';
import { WebhookSecrets } from '../services/webhook-secrets';
import { getWebsiteByDomain } from '../config/db';

const router = Router();

// Generate new webhook secret for a website
router.post('/:domain/webhook-secret', async (req, res) => {
  try {
    const { domain } = req.params;

    // Get website
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    // Generate new secret
    const secret = await WebhookSecrets.createOrUpdateSecret(website.id);

    res.json({ 
      secret,
      instructions: {
        headers: {
          'x-wpfort-signature': 'HMAC SHA256 signature of timestamp.payload',
          'x-wpfort-timestamp': 'Current Unix timestamp in seconds'
        },
        example: `
// PHP Example
$timestamp = time();
$payload = json_encode($data);
$signatureData = $timestamp . '.' . $payload;
$signature = hash_hmac('sha256', $signatureData, '${secret}');

$headers = [
    'x-wpfort-signature: ' . $signature,
    'x-wpfort-timestamp: ' . $timestamp
];`
      }
    });
  } catch (error) {
    console.error('Error generating webhook secret:', error);
    res.status(500).json({ error: error.message });
  }
});

// Delete webhook secret
router.delete('/:domain/webhook-secret', async (req, res) => {
  try {
    const { domain } = req.params;

    // Get website
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    // Delete secret
    await WebhookSecrets.deleteWebhookSecret(website.id);

    res.json({ success: true });
  } catch (error) {
    console.error('Error deleting webhook secret:', error);
    res.status(500).json({ error: error.message });
  }
});

export default router;
