import { Router } from 'express';
import sitesRouter from './sites';
import scansRouter from './scans';
import firewallRouter from './firewall';
import backupsRouter from './backups';
import whitelistsRouter from './whitelists';
import webhooksRouter from './webhooks';
import { verifyWebhook } from '../middleware/verify-webhook';

const router = Router();

// Use HMAC verification for all routes except webhooks
const apiSecret = process.env.WEBHOOK_SECRET_KEY || '';
router.use((req, res, next) => {
  if (!req.path.startsWith('/webhook')) {
    return verifyWebhook(apiSecret)(req, res, next);
  }
  next();
});

// Mount route modules
router.use('/', sitesRouter);
router.use('/', scansRouter);
router.use('/', firewallRouter);
router.use('/', backupsRouter);
router.use('/whitelist', whitelistsRouter);
router.use('/webhook', webhooksRouter);

export default router;
