import { Request, Response, NextFunction } from 'express';
import { logger } from '../services/logger';

export const verifyToken = (req: Request, res: Response, next: NextFunction) => {
  const token = req.headers['x-wpfort-token'];

  // Skip token verification for webhook routes as they use their own auth
  if (req.path.startsWith('/webhooks')) {
    return next();
  }

  if (!token) {
    logger.warn({
      message: 'Missing API token',
      path: req.path,
      ip: req.ip
    }, {
      component: 'auth-middleware',
      event: 'missing_token'
    });
    return res.status(401).json({ error: 'API token is required' });
  }

  // Verify against WPFORT_API_KEY
  if (token !== process.env.WPFORT_API_KEY) {
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
