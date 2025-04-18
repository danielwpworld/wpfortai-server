// IMPORTANT: Load environment variables FIRST, before any other imports
import { config } from 'dotenv';

// Load environment variables synchronously before anything else happens
config({ path: '.env.local' });

// Now that environment variables are loaded, we can import other modules
import express from 'express';
import cors from 'cors';
import morgan from 'morgan';
import { Request, Response, NextFunction } from 'express';
import { logger } from './services/logger';
import router from './routes';

// Required environment variables
const requiredEnvVars = [
  'REDIS_SERVER',
  'REDIS_USERNAME',
  'REDIS_PASSWORD',
  'WPFORT_API_KEY',
  'WPFORT_SERVER_API_KEY',
  'DATABASE_URL',
  'NODE_ENV',
  'LOG_LEVEL',
  'GRAFANA_LOKI_HOST',
  'GRAFANA_LOKI_USER',
  'GRAFANA_LOKI_TOKEN',
  'PORT'
];

// Check for missing environment variables
const missingEnvVars = requiredEnvVars.filter(envVar => !process.env[envVar]);

// If any required environment variables are missing, log an error and exit
if (missingEnvVars.length > 0) {
  logger.error({
    message: 'Missing required environment variables',
    missingVariables: missingEnvVars
  }, {
    component: 'server',
    event: 'startup_error'
  });
  
  console.error('\n❌ ERROR: Missing required environment variables:');
  missingEnvVars.forEach(envVar => console.error(`  - ${envVar}`));
  console.error('\nPlease set these variables in your .env.local file or environment and restart the server.\n');
  
  process.exit(1);
}

// Log startup information
logger.info({
  message: 'Starting WPFort AI server',
  nodeEnv: process.env.NODE_ENV,
  environmentVariablesVerified: true
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
    write: (message: string) => {
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
app.use((req: Request, res: Response, next: NextFunction) => {
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
