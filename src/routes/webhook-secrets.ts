import { Router } from 'express';
import { WebhookSecrets } from '../services/webhook-secrets';
import { getWebsiteByDomain } from '../config/db';
import { logger } from '../services/logger';

const router = Router();

// Generate new webhook secret for a website
router.post('/:domain/webhook-secret', async (req, res) => {
  try {
    const { domain } = req.params;

    logger.debug({
      message: 'Generating new webhook secret',
      domain
    }, {
      component: 'webhook-secrets-controller',
      event: 'generate_secret'
    });

    // Get website
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    // Generate new secret
    logger.debug({
      message: 'Creating/updating webhook secret',
      domain,
      websiteId: website.id
    }, {
      component: 'webhook-secrets-controller',
      event: 'create_update_secret'
    });

    const secret = await WebhookSecrets.createOrUpdateSecret(website.id);

    logger.info({
      message: 'Webhook secret generated successfully',
      domain,
      websiteId: website.id
    }, {
      component: 'webhook-secrets-controller',
      event: 'secret_generated'
    });

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
  } catch (error: any) {
    const errorDomain = req.params.domain;
    logger.error({
      message: 'Error generating webhook secret',
      error,
      domain: errorDomain
    }, {
      component: 'webhook-secrets-controller',
      event: 'secret_generation_error'
    });
    res.status(500).json({ error: error.message });
  }
});

// Delete webhook secret
router.delete('/:domain/webhook-secret', async (req, res) => {
  try {
    const { domain } = req.params;

    logger.debug({
      message: 'Deleting webhook secret',
      domain
    }, {
      component: 'webhook-secrets-controller',
      event: 'delete_secret'
    });

    // Get website
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    // Delete secret
    logger.debug({
      message: 'Deleting webhook secret',
      domain,
      websiteId: website.id
    }, {
      component: 'webhook-secrets-controller',
      event: 'delete_secret_request'
    });

    await WebhookSecrets.deleteWebhookSecret(website.id);

    logger.info({
      message: 'Webhook secret deleted successfully',
      domain,
      websiteId: website.id
    }, {
      component: 'webhook-secrets-controller',
      event: 'secret_deleted'
    });

    res.json({ success: true });
  } catch (error: any) {
    const errorDomain = req.params.domain;
    logger.error({
      message: 'Error deleting webhook secret',
      error,
      domain: errorDomain
    }, {
      component: 'webhook-secrets-controller',
      event: 'secret_deletion_error'
    });
    res.status(500).json({ error: error.message });
  }
});

export default router;
