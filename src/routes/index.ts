import { Router } from 'express';
import sitesRouter from './sites';
import scansRouter from './scans';
import firewallRouter from './firewall';
import backupsRouter from './backups';
import whitelistsRouter from './whitelists';
import webhooksRouter from './webhooks';
import webhookSecretsRouter from './webhook-secrets';
import { verifyToken } from '../middleware/verify-token';

const router = Router();

// Apply token verification middleware to all routes
// Webhook routes will be skipped as handled in the middleware itself
router.use(verifyToken);

// Mount route modules with clear path prefixes
router.use('/sites', sitesRouter);
router.use('/scans', scansRouter);
router.use('/firewall', firewallRouter);
router.use('/backups', backupsRouter);
router.use('/whitelist', whitelistsRouter);
router.use('/webhooks', webhooksRouter);
router.use('/webhook-secrets', webhookSecretsRouter);

export default router;
