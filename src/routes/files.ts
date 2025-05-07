import { Router } from 'express';
import { WPSecAPI } from '../services/wpsec';
import { getWebsiteByDomain } from '../config/db';
import { logger } from '../services/logger';

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
    res.status(500).json({ error: err.message });
  }
});

export default router;
