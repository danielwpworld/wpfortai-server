import { Request, Response, NextFunction } from 'express';
import { logger } from '../services/logger';

export const verifyToken = (req: Request, res: Response, next: NextFunction) => {
  const token = req.headers['x-wpfort-token'];

  // Debug log for all requests
  logger.debug({
    message: 'Token verification middleware called',
    path: req.path,
    method: req.method,
    hasToken: !!token
  }, {
    component: 'auth-middleware',
    event: 'verify_token_called'
  });

  // Skip token verification for webhook routes as they use their own auth
  if (req.path.includes('/webhook')) {
    logger.debug({
      message: 'Skipping token verification for webhook route',
      path: req.path
    }, {
      component: 'auth-middleware',
      event: 'webhook_skip'
    });
    return next();
  }

  if (!token) {
    logger.warn({
      message: 'Missing API token',
      path: req.path,
      ip: req.ip,
      headers: req.headers
    }, {
      component: 'auth-middleware',
      event: 'missing_token'
    });
    return res.status(401).json({ error: 'API token is required' });
  }

  // Verify against WPFORT_BACKEND_API_KEY  
  if (token !== process.env.WPFORT_SERVER_API_KEY) {
    logger.warn({
      message: 'Invalid API token',
      path: req.path,
      ip: req.ip
    }, {
      component: 'auth-middleware',
      event: 'invalid_token'
    });
    return res.status(401).json({ error: 'Invalid API token' });
  }

  next();
};
