import { Router } from 'express';
import sitesRouter from './sites';
import scansRouter from './scans';
import webhooksRouter from './webhooks';
import firewallRouter from './firewall';
import whitelistsRouter from './whitelists';
import backupsRouter from './backups';
import webhookSecretsRouter from './webhook-secrets';

const router = Router();

// Mount routes
router.use('/sites', sitesRouter);
router.use('/scans', scansRouter);
router.use('/firewall', firewallRouter);
router.use('/backups', backupsRouter);
router.use('/webhook-secrets', webhookSecretsRouter);
router.use('/whitelist', whitelistsRouter);
router.use('/webhooks', webhooksRouter);

export default router;
