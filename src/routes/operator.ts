import { Router } from 'express';
import { getWebsiteByDomain } from '../config/db';
import pool from '../config/db';
import { logger } from '../services/logger';
import { randomBytes } from 'crypto';
import redis from '../config/redis';

const router = Router();

// Helper function to generate random string
const generateRandomString = (length: number): string => {
  return randomBytes(Math.ceil(length / 2))
    .toString('hex')
    .slice(0, length);
};

// Assessment Redis Entry interface
interface AssessmentRedisEntry {
  assessment_id: string;      // Unique ID (assess_[20chars])
  website_id: string;         // UUID of the website
  domain: string;             // Domain of the website
  status: 'pending' | 'processing' | 'completed' | 'failed';
  started_at: string;         // ISO timestamp
  completed_at?: string;      // ISO timestamp when completed
  error?: string;             // Error message if failed
  results?: any;              // Results from AI middleware
}

// Assessment Store Service
export class AssessmentStore {
  private static readonly ASSESSMENT_KEY_PREFIX = 'assessment:';
  static readonly ACTIVE_ASSESSMENT_KEY_PREFIX = 'active_assessment:'; // Made public for access in route handlers
  private static readonly ASSESSMENT_TTL = 60 * 60 * 24 * 7; // 7 days in seconds
  
  // Check if an active assessment exists for a domain
  static async getActiveAssessment(domain: string): Promise<AssessmentRedisEntry | null> {
    // Get the active assessment ID for this domain
    const activeAssessmentId = await redis.get(`${this.ACTIVE_ASSESSMENT_KEY_PREFIX}${domain}`);
    if (!activeAssessmentId) return null;
    
    // Get the assessment data
    return this.getAssessment(activeAssessmentId);
  }
  
  // Remove the active assessment for a domain
  static async removeActiveAssessment(domain: string): Promise<void> {
    await redis.del(`${this.ACTIVE_ASSESSMENT_KEY_PREFIX}${domain}`);
  }
  
  // Create a new assessment
  static async createAssessment(domain: string, websiteId: string): Promise<string> {
    // Generate a new assessment ID
    const assessmentId = `assess_${generateRandomString(20)}`;
    const key = `${this.ASSESSMENT_KEY_PREFIX}${assessmentId}`;
    
    const data: AssessmentRedisEntry = {
      assessment_id: assessmentId,
      website_id: websiteId, // Ensuring website_id is UUID as required
      domain,
      status: 'pending',
      started_at: new Date().toISOString()
    };
    
    // Use a Redis transaction to ensure atomicity
    const multi = redis.multi();
    
    // Store assessment data with TTL
    multi.setex(key, this.ASSESSMENT_TTL, JSON.stringify(data));
    
    // Set this assessment as the active assessment for the domain
    multi.setex(
      `${this.ACTIVE_ASSESSMENT_KEY_PREFIX}${domain}`,
      this.ASSESSMENT_TTL,
      assessmentId
    );
    
    await multi.exec();
    return assessmentId;
  }
  
  // Get assessment by ID
  static async getAssessment(assessmentId: string): Promise<AssessmentRedisEntry | null> {
    const key = `${this.ASSESSMENT_KEY_PREFIX}${assessmentId}`;
    const data = await redis.get(key);
    
    if (!data) return null;
    return JSON.parse(data) as AssessmentRedisEntry;
  }
  
  // Update assessment status
  static async updateStatus(
    assessmentId: string, 
    status: AssessmentRedisEntry['status'], 
    results?: any, 
    error?: string
  ): Promise<void> {
    const key = `${this.ASSESSMENT_KEY_PREFIX}${assessmentId}`;
    const data = await this.getAssessment(assessmentId);
    
    if (!data) throw new Error(`Assessment ${assessmentId} not found`);
    
    const updatedData: AssessmentRedisEntry = {
      ...data,
      status,
      ...(status === 'completed' || status === 'failed' ? { completed_at: new Date().toISOString() } : {}),
      ...(results ? { results } : {}),
      ...(error ? { error } : {})
    };
    
    // Update with the same TTL
    await redis.setex(key, this.ASSESSMENT_TTL, JSON.stringify(updatedData));
  }
}

/**
 * POST /api/operator/:domain/assessment
 * Initiates a new assessment for the website
 */
router.post('/:domain/assessment', async (req, res) => {
  try {
    const { domain } = req.params;
    
    logger.debug({
      message: 'Starting new assessment',
      domain
    }, {
      component: 'operator-controller',
      event: 'assessment_start_request'
    });
    
    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }
    
    // Check if there's already an active assessment for this domain
    const activeAssessment = await AssessmentStore.getActiveAssessment(domain);
    if (activeAssessment) {
      // If the assessment is completed or failed, we can create a new one
      if (activeAssessment.status !== 'pending' && activeAssessment.status !== 'processing') {
        // Remove the active assessment reference to allow a new assessment
        await AssessmentStore.removeActiveAssessment(domain);
      } else {
        // Otherwise, return the existing assessment ID
        logger.info({
          message: 'Active assessment already exists',
          domain,
          assessmentId: activeAssessment.assessment_id,
          status: activeAssessment.status
        }, {
          component: 'operator-controller',
          event: 'assessment_already_active'
        });
        
        return res.status(409).json({
          status: 'error',
          message: 'An assessment is already in progress for this domain',
          assessment_id: activeAssessment.assessment_id,
          assessment_status: activeAssessment.status
        });
      }
    }
    
    // Create a new assessment
    const assessmentId = await AssessmentStore.createAssessment(domain, website.id);
    
    logger.info({
      message: 'Assessment created successfully',
      domain,
      assessmentId,
      websiteId: website.id
    }, {
      component: 'operator-controller',
      event: 'assessment_created'
    });
    
    // Return the assessment ID
    res.status(200).json({ 
      status: 'success',
      assessment_id: assessmentId,
      message: 'Assessment initiated successfully'
    });
    
    // Note: The actual assessment processing will be handled by a worker
    // This endpoint only initiates the process and returns immediately
    
  } catch (error) {
    const err = error instanceof Error ? error : new Error(String(error) || 'Unknown error');
    logger.error({
      message: 'Error creating assessment',
      error: err,
      domain: req.params.domain
    }, {
      component: 'operator-controller',
      event: 'assessment_create_error'
    });
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/operator/:domain/assessment/:assessmentId/status
 * Gets the status of an assessment
 */
router.get('/:domain/assessment/:assessmentId/status', async (req, res) => {
  try {
    const { domain, assessmentId } = req.params;
    
    logger.debug({
      message: 'Getting assessment status',
      domain,
      assessmentId
    }, {
      component: 'operator-controller',
      event: 'get_assessment_status'
    });
    
    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }
    
    // Get assessment from Redis
    const assessment = await AssessmentStore.getAssessment(assessmentId);
    if (!assessment) {
      return res.status(404).json({ error: 'Assessment not found' });
    }
    
    // Verify that the assessment belongs to the requested domain
    if (assessment.domain !== domain) {
      return res.status(403).json({ error: 'Assessment does not belong to this domain' });
    }
    
    logger.debug({
      message: 'Assessment status retrieved',
      domain,
      assessmentId,
      status: assessment.status
    }, {
      component: 'operator-controller',
      event: 'assessment_status_retrieved'
    });
    
    // Return the assessment status and results if available
    const response: any = {
      status: 'success',
      assessment_id: assessmentId,
      assessment_status: assessment.status,
      started_at: assessment.started_at
    };
    
    if (assessment.completed_at) {
      response.completed_at = assessment.completed_at;
    }
    
    if (assessment.error) {
      response.error = assessment.error;
    }
    
    if (assessment.status === 'completed' && assessment.results) {
      response.results = assessment.results;
    }
    
    res.json(response);
    
  } catch (error) {
    const err = error instanceof Error ? error : new Error(String(error) || 'Unknown error');
    logger.error({
      message: 'Error getting assessment status',
      error: err,
      domain: req.params.domain,
      assessmentId: req.params.assessmentId
    }, {
      component: 'operator-controller',
      event: 'assessment_status_error'
    });
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/operator/:domain/assessment/active
 * Gets the active assessment for a domain if one exists
 */
router.get('/:domain/assessment/active', async (req, res) => {
  try {
    const { domain } = req.params;
    
    logger.debug({
      message: 'Checking for active assessment',
      domain
    }, {
      component: 'operator-controller',
      event: 'check_active_assessment'
    });
    
    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }
    
    // Check if there's an active assessment for this domain
    const activeAssessment = await AssessmentStore.getActiveAssessment(domain);
    if (!activeAssessment) {
      return res.status(404).json({
        status: 'not_found',
        message: 'No active assessment found for this domain'
      });
    }
    
    logger.debug({
      message: 'Active assessment found',
      domain,
      assessmentId: activeAssessment.assessment_id,
      status: activeAssessment.status
    }, {
      component: 'operator-controller',
      event: 'active_assessment_found'
    });
    
    // Return the assessment status and results if available
    const response: any = {
      status: 'success',
      assessment_id: activeAssessment.assessment_id,
      assessment_status: activeAssessment.status,
      started_at: activeAssessment.started_at
    };
    
    if (activeAssessment.completed_at) {
      response.completed_at = activeAssessment.completed_at;
    }
    
    if (activeAssessment.error) {
      response.error = activeAssessment.error;
    }
    
    if (activeAssessment.status === 'completed' && activeAssessment.results) {
      response.results = activeAssessment.results;
    }
    
    res.json(response);
    
  } catch (error) {
    const err = error instanceof Error ? error : new Error(String(error) || 'Unknown error');
    logger.error({
      message: 'Error checking for active assessment',
      error: err,
      domain: req.params.domain
    }, {
      component: 'operator-controller',
      event: 'check_active_assessment_error'
    });
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/operator/:domain/actions/execute
 * Creates Redis entries for action worker to process selected action items
 */
router.post('/:domain/actions/execute', async (req, res) => {
  try {
    const { domain } = req.params;
    const { action_ids } = req.body;
    
    if (!Array.isArray(action_ids) || action_ids.length === 0) {
      return res.status(400).json({ error: 'action_ids must be a non-empty array of UUIDs or action names' });
    }
    
    // Check if we received action names instead of UUIDs
    const isUuid = (id: string) => {
      return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id);
    };
    
    const containsUuids = action_ids.every(id => isUuid(id));
    const containsActionNames = !containsUuids;
    
    logger.debug({
      message: 'Creating action jobs in Redis',
      domain,
      action_count: action_ids.length
    }, {
      component: 'operator-controller',
      event: 'create_action_jobs'
    });
    
    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }
    
    // Get action items from database
    let query;
    let queryParams;
    
    if (containsUuids) {
      // If we received UUIDs, query by ID
      query = `
        SELECT ai.id, ai.action, ai.data, ai.risk_score, ai.description, wa.website_id, w.domain
        FROM assessment_action_items ai
        JOIN website_assessments wa ON ai.assessment_id = wa.id
        JOIN websites w ON wa.website_id = w.id
        WHERE ai.id = ANY($1::uuid[]) AND w.domain = $2
      `;
      queryParams = [action_ids, domain];
    } else {
      // If we received action names, query by action name
      query = `
        SELECT ai.id, ai.action, ai.data, ai.risk_score, ai.description, wa.website_id, w.domain
        FROM assessment_action_items ai
        JOIN website_assessments wa ON ai.assessment_id = wa.id
        JOIN websites w ON wa.website_id = w.id
        WHERE ai.action = ANY($1) AND w.domain = $2
      `;
      queryParams = [action_ids, domain];
    }
    
    const { rows: actionItems } = await pool.query(query, queryParams);
    
    if (actionItems.length === 0) {
      return res.status(404).json({ 
        error: 'No matching action items found for the provided IDs and domain' 
      });
    }
    
    // Check for existing in-progress actions of the same type
    // First, get all keys matching the action: prefix
    const actionKeys = await redis.keys('action:*');
    const existingActionsPromises = actionKeys.map(async (key) => {
      const data = await redis.get(key);
      if (data) {
        return JSON.parse(data);
      }
      return null;
    });
    
    const existingActions = (await Promise.all(existingActionsPromises)).filter(Boolean);
    
    // Filter out action items that already have in-progress actions of the same type
    const filteredActionItems = actionItems.filter(item => {
      const hasInProgressAction = existingActions.some(action => 
        action.action_type === item.action && 
        action.domain === domain && 
        (action.status === 'pending' || action.status === 'in_progress')
      );
      
      if (hasInProgressAction) {
        logger.warn({
          message: 'Skipping action creation - already in progress',
          domain,
          action_type: item.action,
          action_id: item.id
        }, {
          component: 'operator-controller',
          event: 'action_already_in_progress'
        });
      }
      
      return !hasInProgressAction;
    });
    
    if (filteredActionItems.length === 0) {
      return res.status(409).json({
        error: 'All requested actions already have in-progress instances',
        message: 'Cannot create duplicate in-progress actions of the same type'
      });
    }
    
    // Create Redis entries for each filtered action item
    const currentTime = new Date().toISOString();
    const actionPromises = filteredActionItems.map(async (item: {
      id: string;
      action: string;
      data: any;
      website_id: string;
      domain: string;
    }) => {
      const actionKey = `action:${item.id}`;
      const actionData = {
        id: item.id,
        status: 'pending',
        created_at: currentTime,
        action_type: item.action,
        website_id: item.website_id,
        domain: item.domain,
        data: item.data
      };
      
      // Store in Redis with 7-day TTL (same as assessments)
      await redis.setex(actionKey, 60 * 60 * 24 * 7, JSON.stringify(actionData));
      
      return item.id;
    });
    
    const processedActionIds = await Promise.all(actionPromises);
    
    logger.info({
      message: 'Action jobs created successfully',
      domain,
      action_count: processedActionIds.length,
      action_ids: processedActionIds
    }, {
      component: 'operator-controller',
      event: 'action_jobs_created'
    });
    
    res.status(200).json({
      status: 'success',
      message: 'Action jobs created successfully',
      action_count: processedActionIds.length,
      action_ids: processedActionIds
    });
    
  } catch (error) {
    const err = error instanceof Error ? error : new Error(String(error) || 'Unknown error');
    logger.error({
      message: 'Error creating action jobs',
      error: err,
      domain: req.params.domain
    }, {
      component: 'operator-controller',
      event: 'create_action_jobs_error'
    });
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/operator/:domain/actions/:actionId/status
 * Gets the status of an action from both Redis and database
 */
router.get('/:domain/actions/:actionId/status', async (req, res) => {
  try {
    const { domain, actionId } = req.params;
    
    logger.debug({
      message: 'Getting action status',
      domain,
      actionId
    }, {
      component: 'operator-controller',
      event: 'get_action_status'
    });
    
    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }
    
    // Check if actionId is a UUID or an action name
    const isUuid = (id: string) => {
      return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id);
    };
    
    const isActionIdUuid = isUuid(actionId);
    
    // First check Redis for the most up-to-date status
    // If it's a UUID, use it directly as the key
    let redisData = null;
    if (isActionIdUuid) {
      const actionKey = `action:${actionId}`;
      redisData = await redis.get(actionKey);
    } else {
      // If it's an action name, we need to scan Redis for keys with matching action_type
      // This is more complex and would require scanning all action keys
      // For now, we'll skip Redis lookup for action names and rely on the database
    }
    
    // Then check the database for the action item
    let query;
    let queryParams;
    
    if (isActionIdUuid) {
      // If we received a UUID, query by ID
      query = `
        SELECT ai.id, ai.action, ai.data, ai.risk_score, ai.description, ai.status, 
               ai.created_at, ai.updated_at, ai.status_updated_at, 
               wa.website_id, w.domain
        FROM assessment_action_items ai
        JOIN website_assessments wa ON ai.assessment_id = wa.id
        JOIN websites w ON wa.website_id = w.id
        WHERE ai.id = $1::uuid AND w.domain = $2
      `;
      queryParams = [actionId, domain];
    } else {
      // If we received an action name, query by action name
      query = `
        SELECT ai.id, ai.action, ai.data, ai.risk_score, ai.description, ai.status, 
               ai.created_at, ai.updated_at, ai.status_updated_at, 
               wa.website_id, w.domain
        FROM assessment_action_items ai
        JOIN website_assessments wa ON ai.assessment_id = wa.id
        JOIN websites w ON wa.website_id = w.id
        WHERE ai.action = $1 AND w.domain = $2
      `;
      queryParams = [actionId, domain];
    }
    
    const { rows } = await pool.query(query, queryParams);
    const dbAction = rows[0];
    
    // If neither Redis nor DB has the action, return 404
    if (!redisData && !dbAction) {
      return res.status(404).json({ error: 'Action not found' });
    }
    
    // Prepare response based on available data
    const response: any = {
      status: 'success',
      action_id: actionId,
      domain
    };
    
    // If Redis has data, it's the most current for in-progress actions
    if (redisData) {
      const actionData = JSON.parse(redisData);
      response.redis_status = actionData.status;
      response.created_at = actionData.created_at;
      response.action_type = actionData.action_type;
      response.data = actionData.data;
      
      // Include any result data if available
      if (actionData.result) {
        response.result = actionData.result;
      }
      
      // Include any error if available
      if (actionData.error) {
        response.error = actionData.error;
      }
    }
    
    // If DB has data, include it (this is the permanent record)
    if (dbAction) {
      response.db_status = dbAction.status;
      response.db_created_at = dbAction.created_at;
      response.db_updated_at = dbAction.updated_at;
      response.db_status_updated_at = dbAction.status_updated_at;
      response.action_type = dbAction.action;
      response.description = dbAction.description;
      response.risk_score = dbAction.risk_score;
      response.data = dbAction.data;
    }
    
    // Determine the final status (Redis takes precedence if available)
    response.status_source = redisData ? 'redis' : 'database';
    response.current_status = redisData ? JSON.parse(redisData).status : dbAction.status;
    
    logger.debug({
      message: 'Action status retrieved',
      domain,
      actionId,
      status: response.current_status,
      statusSource: response.status_source
    }, {
      component: 'operator-controller',
      event: 'action_status_retrieved'
    });
    
    res.json(response);
    
  } catch (error) {
    const err = error instanceof Error ? error : new Error(String(error) || 'Unknown error');
    logger.error({
      message: 'Error getting action status',
      error: err,
      domain: req.params.domain,
      actionId: req.params.actionId
    }, {
      component: 'operator-controller',
      event: 'action_status_error'
    });
    res.status(500).json({ error: err.message });
  }
});

export default router;
