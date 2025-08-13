import { Router, Request, Response } from 'express';
import { logger } from '../services/logger';
import admin from 'firebase-admin';
import pool from '../config/db';

const router = Router();

// Initialize Firebase Admin SDK if not already initialized
if (!admin.apps.length) {
  // Firebase Admin SDK will use the default service account from environment
  // Make sure GOOGLE_APPLICATION_CREDENTIALS is set in your environment
  admin.initializeApp({
    credential: admin.credential.applicationDefault(),
  });
}

interface CreateVerifiedUserRequest {
  uid: string;
  email: string;
  auth_type: string;
  firebaseToken: string;
}

// POST /users/verify-and-create
// Verify Firebase token and email verification status, then create user in database
router.post('/verify-and-create', async (req: Request, res: Response) => {
  try {
    const { uid, email, auth_type, firebaseToken }: CreateVerifiedUserRequest = req.body;

    logger.info({
      message: 'Creating verified user request received',
      uid,
      email,
      auth_type
    }, {
      component: 'users-route',
      event: 'verify_and_create_request'
    });

    // Validate required fields
    if (!uid || !email || !auth_type || !firebaseToken) {
      logger.warn({
        message: 'Missing required fields for verified user creation',
        provided: { uid: !!uid, email: !!email, auth_type: !!auth_type, firebaseToken: !!firebaseToken }
      }, {
        component: 'users-route',
        event: 'validation_error'
      });
      
      return res.status(400).json({ 
        error: 'Missing required fields: uid, email, auth_type, and firebaseToken are required' 
      });
    }

    // Verify Firebase token and get user
    let decodedToken;
    try {
      decodedToken = await admin.auth().verifyIdToken(firebaseToken);
      
      if (decodedToken.uid !== uid) {
        logger.warn({
          message: 'UID mismatch in token verification',
          tokenUid: decodedToken.uid,
          requestUid: uid
        }, {
          component: 'users-route',
          event: 'uid_mismatch'
        });
        
        return res.status(401).json({ error: 'Token UID does not match request UID' });
      }
    } catch (error) {
      logger.error({
        message: 'Firebase token verification failed',
        error: error instanceof Error ? error : new Error(String(error))
      }, {
        component: 'users-route',
        event: 'token_verification_failed'
      });
      
      return res.status(401).json({ error: 'Invalid Firebase token' });
    }

    // Get Firebase user to check email verification status
    let firebaseUser;
    try {
      firebaseUser = await admin.auth().getUser(uid);
    } catch (error) {
      logger.error({
        message: 'Failed to get Firebase user',
        uid,
        error: error instanceof Error ? error : new Error(String(error))
      }, {
        component: 'users-route',
        event: 'firebase_user_fetch_failed'
      });
      
      return res.status(404).json({ error: 'Firebase user not found' });
    }

    // Check if email is verified (skip for Google SSO users)
    if (auth_type === 'email' && !firebaseUser.emailVerified) {
      logger.warn({
        message: 'Email not verified for user creation',
        uid,
        email,
        emailVerified: firebaseUser.emailVerified
      }, {
        component: 'users-route',
        event: 'email_not_verified'
      });
      
      return res.status(400).json({ error: 'Email not verified' });
    }

    // Create user directly in database
    try {
      // Check if user already exists
      const existingUserQuery = 'SELECT * FROM users WHERE uid = $1';
      const existingUserResult = await pool.query(existingUserQuery, [uid]);

      if (existingUserResult.rows.length > 0) {
        const existingUser = existingUserResult.rows[0];
        
        logger.info({
          message: 'User already exists in database',
          uid,
          email
        }, {
          component: 'users-route',
          event: 'user_already_exists'
        });

        return res.status(200).json({
          success: true,
          user: {
            uid: existingUser.uid,
            email: existingUser.email,
            plan: existingUser.plan,
            auth_type: existingUser.auth_type
          },
          message: 'User verified and retrieved successfully'
        });
      }

      // Create new user
      const plan = 'Free'; // Default plan
      const createUserQuery = `
        INSERT INTO users (uid, email, plan, auth_type)
        VALUES ($1, $2, $3, $4)
        RETURNING *
      `;
      
      const createUserResult = await pool.query(createUserQuery, [uid, email, plan, auth_type]);
      const newUser = createUserResult.rows[0];

      logger.info({
        message: 'User verified and created successfully',
        uid,
        email,
        auth_type,
        emailVerified: firebaseUser.emailVerified
      }, {
        component: 'users-route',
        event: 'user_created_successfully'
      });

      res.status(201).json({
        success: true,
        user: {
          uid: newUser.uid,
          email: newUser.email,
          plan: newUser.plan,
          auth_type: newUser.auth_type
        },
        message: 'User verified and created successfully'
      });

    } catch (dbError) {
      logger.error({
        message: 'Error creating user in database',
        uid,
        email,
        error: dbError instanceof Error ? dbError : new Error(String(dbError))
      }, {
        component: 'users-route',
        event: 'database_user_creation_error'
      });

      return res.status(500).json({ error: 'Failed to create user in database' });
    }

  } catch (error) {
    logger.error({
      message: 'Error in verify-and-create endpoint',
      error: error instanceof Error ? error : new Error(String(error)),
      stack: error instanceof Error ? error.stack : undefined
    }, {
      component: 'users-route',
      event: 'endpoint_error'
    });

    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;