import { Router } from 'express';
import { WPSecAPI } from '../services/wpsec';
import { getWebsiteByDomain } from '../config/db';
import { logger } from '../services/logger';
import fetch from 'node-fetch';

const router = Router();

/**
 * Inspect a file to get detailed information and potential detections
 * POST /:domain/inspect-file
 * Body: { file_path: string }
 */
router.post('/:domain/inspect-file', async (req, res) => {
  try {
    const { domain } = req.params;
    const { file_path } = req.body;

    if (!file_path) {
      return res.status(400).json({ error: 'file_path is required' });
    }

    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    // Create WPSec API instance
    const api = new WPSecAPI(domain);

    // Log the inspection request
    logger.debug({
      message: 'Inspecting file',
      domain,
      filePath: file_path,
      websiteId: website.id
    }, {
      component: 'file-controller',
      event: 'inspect_file'
    });

    // Call the WPSec API to inspect the file
    const result = await api.inspectFile(file_path);

    logger.info({
      message: 'File inspection completed',
      domain,
      filePath: file_path,
      detectionCount: result.file_info?.detection_count || 0
    }, {
      component: 'file-controller',
      event: 'file_inspected'
    });

    res.json(result);
  } catch (error) {
    const err = error instanceof Error ? error : new Error(String(error) || 'Unknown error');
    logger.error({
      message: 'Error inspecting file',
      error: err,
      domain: req.params.domain,
      filePath: req.body.file_path
    }, {
      component: 'file-controller',
      event: 'inspect_file_error'
    });
    res.status(500).json({ error: err.message });
  }
});

/**
 * Fix file/directory permissions on the WordPress site
 * POST /:domain/fix-permissions
 * Body: 
 *   { fix_all: true } 
 * OR 
 *   { path: string, recursive: boolean, type: 'file'|'directory' }
 */
router.post('/:domain/fix-permissions', async (req, res) => {
  try {
    const { domain } = req.params;
    const { fix_all, path, recursive, type } = req.body;

    // Validate request body
    if (!fix_all && !path) {
      return res.status(400).json({ 
        error: 'Either fix_all or path must be provided' 
      });
    }

    if (path && !type) {
      return res.status(400).json({ 
        error: 'When specifying a path, type (file or directory) must be provided' 
      });
    }

    if (type && !['file', 'directory'].includes(type)) {
      return res.status(400).json({ 
        error: 'Type must be either "file" or "directory"' 
      });
    }

    // Check if website exists
    const website = await getWebsiteByDomain(domain);
    if (!website) {
      return res.status(404).json({ error: 'Website not found' });
    }

    // Create WPSec API instance
    const api = new WPSecAPI(domain);

    // Log the fix permissions request
    logger.debug({
      message: 'Fixing permissions',
      domain,
      websiteId: website.id,
      fixAll: !!fix_all,
      path,
      recursive,
      type
    }, {
      component: 'files-controller',
      event: 'fix_permissions_request'
    });

    // Call the WPSec API to fix permissions
    const result = await api.fixPermissions({
      fix_all: fix_all,
      path,
      recursive,
      type: type as 'file' | 'directory'
    });

    logger.info({
      message: 'Permissions fixed successfully',
      domain,
      fixAll: !!fix_all,
      path,
      recursive,
      type
    }, {
      component: 'files-controller',
      event: 'permissions_fixed'
    });

    // Create and broadcast permissions fix completed event
    try {
      // Construct event data with proper typing
      const eventData: {
        origin: string;
        vertical: string;
        status: string;
        message: string;
        fixed_at: string;
        file_info?: {
          path: string;
          recursive: boolean;
          type: string;
        };
      } = {
        origin: 'backend',
        vertical: 'wpcore_layer',
        status: 'success',
        message: fix_all 
          ? 'WordPress core files permissions fixed successfully.' 
          : 'Fixed permissions for WordPress core files.',
        fixed_at: new Date().toISOString()
      };
      
      // Add path information to metadata if specific file/directory was fixed
      if (path) {
        eventData.file_info = {
          path,
          recursive: !!recursive,
          type
        };
      }
      
      // First store event in database, then broadcast
      const eventResponse = await fetch(`http://localhost:${process.env.PORT || 3001}/api/events/create`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-wpfort-token': process.env.INTERNAL_API_TOKEN || '123123123'
        },
        body: JSON.stringify({
          domain,
          event: 'wpcore_layer.permissions_fix.completed',
          data: eventData
        })
      });
      
      if (eventResponse.ok) {
        logger.info({
          message: 'Successfully created and broadcast permissions fix completed event',
          domain,
          fixAll: !!fix_all,
          path
        }, {
          component: 'files-controller',
          event: 'permissions_fix_event_created'
        });
      } else {
        logger.warn({
          message: 'Failed to create permissions fix completed event',
          domain,
          fixAll: !!fix_all,
          path,
          status: eventResponse.status
        }, {
          component: 'files-controller',
          event: 'permissions_fix_event_failed'
        });
      }
    } catch (eventError) {
      logger.error({
        message: 'Error creating permissions fix completed event',
        error: eventError instanceof Error ? eventError : new Error(String(eventError)),
        domain,
        fixAll: !!fix_all,
        path
      }, {
        component: 'files-controller',
        event: 'permissions_fix_event_error'
      });
      // Don't fail the endpoint if event creation fails
    }

    // Run core-check and update wpcore_layer in website_data
    try {
      const coreCheckResult = await api.checkCoreIntegrity();
      // Update the wpcore_layer for this website
      const { updateWPCoreLayer } = await import('../config/db');
      await updateWPCoreLayer(website.id, coreCheckResult);
      logger.info({
        message: 'wpcore_layer updated after fix-permissions',
        domain,
        websiteId: website.id
      }, {
        component: 'files-controller',
        event: 'wpcore_layer_updated_after_fix_permissions'
      });
    } catch (coreErr) {
      logger.error({
        message: 'Failed to update wpcore_layer after fix-permissions',
        error: coreErr instanceof Error ? coreErr : new Error(String(coreErr) || 'Unknown error'),
        domain,
        websiteId: website.id
      }, {
        component: 'files-controller',
        event: 'wpcore_layer_update_failed_after_fix_permissions'
      });
      // Do not fail the main response if this step fails
    }

    res.json(result);
  } catch (error) {
    const err = error instanceof Error ? error : new Error(String(error) || 'Unknown error');
    logger.error({
      message: 'Error fixing permissions',
      error: err,
      domain: req.params.domain,
      fixAll: !!req.body.fix_all,
      path: req.body.path
    }, {
      component: 'files-controller',
      event: 'fix_permissions_error'
    });
    
    // Create and broadcast permissions fix failed event
    try {
      const domain = req.params.domain;
      const fix_all = !!req.body.fix_all;
      const path = req.body.path;
      const recursive = !!req.body.recursive;
      const type = req.body.type;
      
      // Construct event data with proper typing
      const eventData: {
        origin: string;
        vertical: string;
        status: string;
        message: string;
        error: string;
        failed_at: string;
        file_info?: {
          path: string;
          recursive: boolean;
          type: string;
        };
      } = {
        origin: 'backend',
        vertical: 'wpcore_layer',
        status: 'error',
        message: 'Failed to fix WordPress core files permissions.',
        error: err.message,
        failed_at: new Date().toISOString()
      };
      
      // Add path information to metadata if specific file/directory was being fixed
      if (path) {
        eventData.file_info = {
          path,
          recursive,
          type
        };
      }
      
      // First store event in database, then broadcast
      const eventResponse = await fetch(`http://localhost:${process.env.PORT || 3001}/api/events/create`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-wpfort-token': process.env.INTERNAL_API_TOKEN || '123123123'
        },
        body: JSON.stringify({
          domain,
          event: 'wpcore_layer.permissions_fix.failed',
          data: eventData
        })
      });
      
      if (eventResponse.ok) {
        logger.info({
          message: 'Successfully created and broadcast permissions fix failed event',
          domain,
          fixAll: fix_all,
          path
        }, {
          component: 'files-controller',
          event: 'permissions_fix_failed_event_created'
        });
      } else {
        logger.warn({
          message: 'Failed to create permissions fix failed event',
          domain,
          fixAll: fix_all,
          path,
          status: eventResponse.status
        }, {
          component: 'files-controller',
          event: 'permissions_fix_failed_event_failed'
        });
      }
    } catch (eventError) {
      logger.error({
        message: 'Error creating permissions fix failed event',
        error: eventError instanceof Error ? eventError : new Error(String(eventError)),
        domain: req.params.domain
      }, {
        component: 'files-controller',
        event: 'permissions_fix_failed_event_error'
      });
    }
    
    res.status(500).json({ error: err.message });
  }
});

export default router;
