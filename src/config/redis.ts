import Redis from 'ioredis';
import { logger } from '../services/logger';

// Ensure environment variables are available and log them
const redisServer = process.env.REDIS_SERVER || '';
const redisHost = redisServer ? redisServer.split(':')[0] : 'localhost';
const redisPort = redisServer && redisServer.includes(':') ? redisServer.split(':')[1] : '6379';

// Log connection details for debugging
logger.info({
  message: 'Connecting to Redis server',
  host: redisHost,
  port: redisPort,
  username: process.env.REDIS_USERNAME ? '***' : undefined, // Don't log the actual username
  envVarsLoaded: !!process.env.REDIS_SERVER
}, {
  component: 'redis',
  event: 'connection_init'
});

// Create Redis connection with the extracted host and port
const redis = new Redis({
  host: redisHost,
  port: parseInt(redisPort),
  username: process.env.REDIS_USERNAME,
  password: process.env.REDIS_PASSWORD
});

// Log Redis connection events
redis.on('connect', () => {
  logger.info({
    message: 'Redis connection established'
  }, {
    component: 'redis',
    event: 'connection_established'
  });
});

redis.on('error', (err) => {
  logger.error({
    message: 'Redis connection error',
    error: err
  }, {
    component: 'redis',
    event: 'connection_error'
  });
});

redis.on('close', () => {
  logger.warn({
    message: 'Redis connection closed'
  }, {
    component: 'redis',
    event: 'connection_closed'
  });
});

// Helper functions for managing active scans
export const getActiveScan = async (domain: string) => {
  logger.debug({
    message: 'Getting active scan data',
    domain
  }, {
    component: 'redis',
    event: 'get_active_scan'
  });

  try {
    const data = await redis.get(`active_scan:${domain}`);
    const scan = data ? JSON.parse(data) : null;

    logger.debug({
      message: scan ? 'Active scan found' : 'No active scan found',
      domain,
      found: !!scan
    }, {
      component: 'redis',
      event: 'active_scan_result'
    });

    return scan;
  } catch (error: any) {
    logger.error({
      message: 'Error getting active scan',
      error,
      domain
    }, {
      component: 'redis',
      event: 'get_scan_error'
    });
    throw error;
  }
};

export const setActiveScan = async (domain: string, data: any) => {
  logger.debug({
    message: 'Setting active scan data',
    domain,
    scanId: data.scan_id
  }, {
    component: 'redis',
    event: 'set_active_scan'
  });

  try {
    await redis.set(`active_scan:${domain}`, JSON.stringify(data));

    logger.debug({
      message: 'Active scan data set successfully',
      domain,
      scanId: data.scan_id
    }, {
      component: 'redis',
      event: 'scan_data_set'
    });
  } catch (error: any) {
    logger.error({
      message: 'Error setting active scan',
      error,
      domain
    }, {
      component: 'redis',
      event: 'set_scan_error'
    });
    throw error;
  }
};

export default redis;
