import { Router } from 'express';
import sitesRouter from './sites';
import scansRouter from './scans';
import firewallRouter from './firewall';
import backupsRouter from './backups';
import whitelistsRouter from './whitelists';
import webhooksRouter from './webhooks';
import { verifyToken } from '../middleware/verify-token';

const router = Router();

// Apply token verification middleware to all routes
// Webhook routes will be skipped as handled in the middleware itself
router.use(verifyToken);

// Mount route modules
router.use('/', sitesRouter);
router.use('/', scansRouter);
router.use('/', firewallRouter);
router.use('/', backupsRouter);
router.use('/whitelist', whitelistsRouter);
router.use('/webhook', webhooksRouter);

export default router;
