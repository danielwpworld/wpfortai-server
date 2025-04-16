import * as express from 'express';
import * as cors from 'cors';
import * as morgan from 'morgan';
import { config } from 'dotenv';
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

// Log environment variables
console.log('Environment variables loaded:');
console.log('DATABASE_URL:', process.env.DATABASE_URL);
console.log('WPFORT_API_KEY:', process.env.WPFORT_API_KEY ? '***' : 'not set');

// Create Express app
const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(morgan('dev'));

// API routes
app.use('/api', router);
app.use('/api/backups', backupsRouter);
app.use('/api/webhook-secrets', webhookSecretsRouter);

// Error handling middleware
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error('Error:', err);
  res.status(err.status || 500).json({
    error: err.message || 'Internal Server Error'
  });
});

// Start server
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
