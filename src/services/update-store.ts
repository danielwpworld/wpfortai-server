import redis from '../config/redis';

export type UpdateStatus = 'initializing' | 'in-progress' | 'completed' | 'failed';

export interface UpdateItemStatus {
  slug: string;
  status: UpdateStatus;
  error?: string;
}

export interface StoredUpdateData {
  website_id: string; // UUID of the website
  domain: string;
  update_id: string; // Unique ID for this update operation
  type?: string; // For specific item updates ('plugins', 'themes', or undefined for bulk)
  operation_type?: 'bulk' | 'items'; // Track if this is a bulk update or individual items
  items: UpdateItemStatus[];
  started_at: string;
  status: UpdateStatus; // Overall status
  completed_at?: string;
  error?: string; // Overall error message if failed
}

export class UpdateStore {
  private static readonly UPDATE_KEY_PREFIX = 'update:';
  private static readonly ACTIVE_UPDATE_KEY_PREFIX = 'active_update:';
  private static readonly UPDATE_TTL = 60 * 60 * 24; // 24 hours in seconds

  static async createUpdate(domain: string, websiteId: string, type?: string, itemSlugs: string[] = [], operationType: 'bulk' | 'items' = 'bulk'): Promise<string> {
    // Generate a unique update ID
    const updateId = `upd_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
    
    const items: UpdateItemStatus[] = itemSlugs.map(slug => ({
      slug,
      status: 'initializing'
    }));

    const storedData: StoredUpdateData = {
      website_id: websiteId,
      domain,
      update_id: updateId,
      type,
      operation_type: operationType,
      items,
      started_at: new Date().toISOString(),
      status: 'initializing'
    };

    const multi = redis.multi();
    
    // Store update data with TTL
    multi.setex(
      `${this.UPDATE_KEY_PREFIX}${updateId}`,
      this.UPDATE_TTL,
      JSON.stringify(storedData)
    );

    // Set this update as the active update for the domain
    multi.set(
      `${this.ACTIVE_UPDATE_KEY_PREFIX}${domain}`,
      updateId
    );

    await multi.exec();
    return updateId;
  }

  static async updateStatus(updateId: string, status: UpdateStatus, itemUpdates?: UpdateItemStatus[], error?: string): Promise<void> {
    const key = `${this.UPDATE_KEY_PREFIX}${updateId}`;
    const existingData = await redis.get(key);
    
    if (!existingData) {
      throw new Error(`Update ${updateId} not found in store`);
    }

    const storedData: StoredUpdateData = JSON.parse(existingData);
    
    // Update overall status
    storedData.status = status;
    
    // Set error if provided
    if (error) {
      storedData.error = error;
    }
    
    // If completed or failed, set completed_at
    if (status === 'completed' || status === 'failed') {
      storedData.completed_at = new Date().toISOString();
    }
    
    // Update individual item statuses if provided
    if (itemUpdates && itemUpdates.length > 0) {
      // Create a map of existing items for quick lookup
      const itemMap = new Map<string, UpdateItemStatus>();
      storedData.items.forEach(item => itemMap.set(item.slug, item));
      
      // Update or add items
      itemUpdates.forEach(update => {
        if (itemMap.has(update.slug)) {
          const existingItem = itemMap.get(update.slug)!;
          itemMap.set(update.slug, { ...existingItem, ...update });
        } else {
          storedData.items.push(update);
        }
      });
      
      // Convert map back to array
      storedData.items = Array.from(itemMap.values());
    }

    // For item operations, check if all items are completed or failed to determine overall status
    if (storedData.operation_type === 'items' && storedData.items.length > 0 && status === 'in-progress') {
      const completedItems = storedData.items.filter(item => item.status === 'completed');
      const failedItems = storedData.items.filter(item => item.status === 'failed');
      const totalItems = storedData.items.length;
      
      if (completedItems.length + failedItems.length === totalItems) {
        if (failedItems.length === 0) {
          storedData.status = 'completed';
        } else if (completedItems.length === 0) {
          storedData.status = 'failed';
        } else {
          storedData.status = 'completed'; // Mixed results - some completed, some failed
        }
        storedData.completed_at = new Date().toISOString();
      }
    }

    await redis.setex(key, this.UPDATE_TTL, JSON.stringify(storedData));

    // If update is completed or failed, remove it from active updates
    if (storedData.status === 'completed' || storedData.status === 'failed') {
      await redis.del(`${this.ACTIVE_UPDATE_KEY_PREFIX}${storedData.domain}`);
    }
  }

  static async getUpdate(updateId: string): Promise<StoredUpdateData | null> {
    const data = await redis.get(`${this.UPDATE_KEY_PREFIX}${updateId}`);
    return data ? JSON.parse(data) : null;
  }

  static async getActiveUpdate(domain: string): Promise<StoredUpdateData | null> {
    const updateId = await redis.get(`${this.ACTIVE_UPDATE_KEY_PREFIX}${domain}`);
    if (!updateId) return null;
    return this.getUpdate(updateId);
  }
}
