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

export default router;
