import pool from '../config/db';
import { logger } from './logger';

interface VulnerabilityData {
  fixed_in: string;
  affected_versions?: string;
  [key: string]: any;
}

interface PluginData {
  slug: string;
  version: string;
  latest_version?: string;
  vulnerabilities: VulnerabilityData[];
  update_available?: boolean;
  [key: string]: any;
}

interface ApplicationLayerData {
  plugins: {
    total: number;
    vulnerable: number;
    items: PluginData[];
  };
  themes?: {
    total: number;
    vulnerable: number;
    items: any[];
  };
  [key: string]: any;
}

export class ApplicationLayerUpdater {
  /**
   * Updates a plugin's version and removes fixed vulnerabilities directly in the database
   */
  static async updatePluginInApplicationLayer(
    websiteId: string,
    slug: string,
    newVersion: string,
    itemType: 'plugins' | 'themes' = 'plugins'
  ): Promise<boolean> {
    try {
      logger.info({
        message: 'Starting direct JSON update for plugin',
        websiteId,
        slug,
        newVersion,
        itemType
      }, {
        component: 'application-layer-updater',
        event: 'update_start'
      });

      // Get current application_layer data
      const currentDataResult = await pool.query(
        'SELECT application_layer FROM website_data WHERE website_id = $1',
        [websiteId]
      );

      if (currentDataResult.rows.length === 0) {
        logger.warn({
          message: 'Website data not found for application layer update',
          websiteId,
          slug
        }, {
          component: 'application-layer-updater',
          event: 'website_not_found'
        });
        return false;
      }

      const applicationLayer: ApplicationLayerData = currentDataResult.rows[0].application_layer;
      
      if (!applicationLayer || !applicationLayer[itemType] || !applicationLayer[itemType].items) {
        logger.warn({
          message: `No ${itemType} data found in application layer`,
          websiteId,
          slug,
          itemType
        }, {
          component: 'application-layer-updater',
          event: 'no_items_found'
        });
        return false;
      }

      // Find the plugin/theme in the items array
      const itemIndex = applicationLayer[itemType].items.findIndex(
        (item: PluginData) => item.slug === slug
      );

      if (itemIndex === -1) {
        logger.warn({
          message: `${itemType.slice(0, -1)} not found in application layer`,
          websiteId,
          slug,
          itemType
        }, {
          component: 'application-layer-updater',
          event: 'item_not_found'
        });
        return false;
      }

      const item = applicationLayer[itemType].items[itemIndex];
      const oldVersion = item.version;
      const oldVulnCount = item.vulnerabilities?.length || 0;

      // Update version
      item.version = newVersion;

      // Remove vulnerabilities that are fixed in this version or earlier
      const originalVulnerabilities = item.vulnerabilities || [];
      const remainingVulnerabilities = originalVulnerabilities.filter(vuln => {
        if (!vuln.fixed_in) return true;
        
        // If the new version is >= fixed_in version, remove this vulnerability
        return !this.isVersionGreaterOrEqual(newVersion, vuln.fixed_in);
      });

      item.vulnerabilities = remainingVulnerabilities;
      
      // Update update_available flag
      if (item.latest_version) {
        item.update_available = this.isVersionGreaterOrEqual(item.latest_version, newVersion);
      }

      // Recalculate summary counters
      const vulnerableCount = applicationLayer[itemType].items.filter(
        (item: PluginData) => item.vulnerabilities && item.vulnerabilities.length > 0
      ).length;

      applicationLayer[itemType].vulnerable = vulnerableCount;

      // Update the database with the modified JSON
      await pool.query(
        'UPDATE website_data SET application_layer = $1, fetched_at = NOW() WHERE website_id = $2',
        [JSON.stringify(applicationLayer), websiteId]
      );

      const newVulnCount = remainingVulnerabilities.length;
      const removedVulnCount = oldVulnCount - newVulnCount;

      logger.info({
        message: `Successfully updated ${itemType.slice(0, -1)} in application layer`,
        websiteId,
        slug,
        oldVersion,
        newVersion,
        oldVulnCount,
        newVulnCount,
        removedVulnCount,
        totalVulnerable: vulnerableCount
      }, {
        component: 'application-layer-updater',
        event: 'update_success'
      });

      return true;
    } catch (error) {
      const err = error instanceof Error ? error : new Error(String(error));
      logger.error({
        message: `Failed to update ${itemType.slice(0, -1)} in application layer`,
        error: err,
        websiteId,
        slug,
        newVersion
      }, {
        component: 'application-layer-updater',
        event: 'update_error'
      });
      return false;
    }
  }

  /**
   * Compare two semantic versions to determine if version1 >= version2
   */
  private static isVersionGreaterOrEqual(version1: string, version2: string): boolean {
    try {
      // Clean versions (remove any non-numeric prefixes/suffixes)
      const clean1 = version1.replace(/[^\d.]/g, '');
      const clean2 = version2.replace(/[^\d.]/g, '');
      
      const parts1 = clean1.split('.').map(Number);
      const parts2 = clean2.split('.').map(Number);
      
      // Normalize lengths
      const maxLength = Math.max(parts1.length, parts2.length);
      while (parts1.length < maxLength) parts1.push(0);
      while (parts2.length < maxLength) parts2.push(0);
      
      for (let i = 0; i < maxLength; i++) {
        if (parts1[i] > parts2[i]) return true;
        if (parts1[i] < parts2[i]) return false;
      }
      
      return true; // Equal versions
    } catch (error) {
      logger.warn({
        message: 'Error comparing versions, assuming false',
        version1,
        version2,
        error: error instanceof Error ? error.message : String(error)
      }, {
        component: 'application-layer-updater',
        event: 'version_compare_error'
      });
      return false;
    }
  }

  /**
   * Update multiple plugins/themes at once (for bulk operations)
   */
  static async updateMultipleItems(
    websiteId: string,
    updates: Array<{slug: string, newVersion: string, type?: 'plugins' | 'themes'}>,
    fallbackToAPI: boolean = true
  ): Promise<{success: boolean, updatedCount: number, failedItems: string[]}> {
    let updatedCount = 0;
    const failedItems: string[] = [];

    for (const update of updates) {
      const success = await this.updatePluginInApplicationLayer(
        websiteId,
        update.slug,
        update.newVersion,
        update.type || 'plugins'
      );

      if (success) {
        updatedCount++;
      } else {
        failedItems.push(update.slug);
      }
    }

    // If some updates failed and fallback is enabled, we could implement API fallback here
    if (failedItems.length > 0 && fallbackToAPI) {
      logger.warn({
        message: 'Some items failed to update directly, may need API fallback',
        websiteId,
        failedItems,
        updatedCount,
        totalAttempted: updates.length
      }, {
        component: 'application-layer-updater',
        event: 'partial_update_failure'
      });
    }

    return {
      success: failedItems.length === 0,
      updatedCount,
      failedItems
    };
  }

  /**
   * Get current plugin/theme data from application layer
   */
  static async getItemFromApplicationLayer(
    websiteId: string,
    slug: string,
    itemType: 'plugins' | 'themes' = 'plugins'
  ): Promise<PluginData | null> {
    try {
      const result = await pool.query(
        `SELECT item FROM website_data, 
         jsonb_array_elements(application_layer -> $2 -> 'items') as item 
         WHERE item ->> 'slug' = $3 AND website_id = $1`,
        [websiteId, itemType, slug]
      );

      if (result.rows.length === 0) {
        return null;
      }

      return result.rows[0].item as PluginData;
    } catch (error) {
      logger.error({
        message: `Failed to get ${itemType.slice(0, -1)} from application layer`,
        error: error instanceof Error ? error : new Error(String(error)),
        websiteId,
        slug,
        itemType
      }, {
        component: 'application-layer-updater',
        event: 'get_item_error'
      });
      return null;
    }
  }
}