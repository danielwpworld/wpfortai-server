import * as express from 'express';
import * as cors from 'cors';
import * as morgan from 'morgan';
import { config } from 'dotenv';
import { logger } from './services/logger';
import router from './routes';
import sitesRouter from './routes/sites';
import scansRouter from './routes/scans';
import webhooksRouter from './routes/webhooks';
import firewallRouter from './routes/firewall';
import whitelistsRouter from './routes/whitelists';
import backupsRouter from './routes/backups';
import webhookSecretsRouter from './routes/webhook-secrets';

// Load environment variables
config({ path: '.env.local' });

// Log startup information
logger.info({
  message: 'Starting WPFort AI server',
  nodeEnv: process.env.NODE_ENV,
  databaseConfigured: !!process.env.DATABASE_URL,
  apiKeyConfigured: !!process.env.WPFORT_API_KEY
}, {
  component: 'server',
  event: 'startup'
});

// Create Express app
const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Configure morgan to use our logger
app.use(morgan('dev', {
  stream: {
    write: (message) => {
      logger.debug({
        message: message.trim()
      }, {
        component: 'server',
        event: 'http_request'
      });
    }
  }
}));

// Log all requests
app.use((req, res, next) => {
  logger.debug({
    message: 'Incoming request',
    method: req.method,
    url: req.url,
    ip: req.ip,
    userAgent: req.get('user-agent')
  }, {
    component: 'server',
    event: 'request_start'
  });
  next();
});

// API routes
app.use('/api', router);
app.use('/api/backups', backupsRouter);
app.use('/api/webhook-secrets', webhookSecretsRouter);

// Error handling middleware
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  logger.error({
    message: 'Unhandled error',
    error: err,
    method: req.method,
    url: req.url,
    ip: req.ip,
    statusCode: err.status || 500
  }, {
    component: 'server',
    event: 'unhandled_error'
  });

  res.status(err.status || 500).json({
    error: err.message || 'Internal Server Error'
  });
});

// Start server
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  logger.info({
    message: 'Server started successfully',
    port: PORT,
    nodeEnv: process.env.NODE_ENV,
    pid: process.pid
  }, {
    component: 'server',
    event: 'server_started'
  });
});
