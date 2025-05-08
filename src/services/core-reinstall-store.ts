import redis from '../config/redis';

export interface StoredCoreReinstallData {
  domain: string;
  operation_id: string;
  started_at: string;
  status: string;
  message?: string;
  version?: string;
  completed_at?: string;
  error_message?: string;
  check_status_endpoint?: string;
}

export class CoreReinstallStore {
  private static readonly KEY_PREFIX = 'core_reinstall:';
  private static readonly ACTIVE_KEY_PREFIX = 'active_core_reinstall:';
  private static readonly TTL = 60 * 60 * 24; // 24 hours

  static async createCoreReinstall(domain: string, data: StoredCoreReinstallData): Promise<void> {
    const multi = redis.multi();
    multi.setex(
      `${this.KEY_PREFIX}${data.operation_id}`,
      this.TTL,
      JSON.stringify(data)
    );
    multi.set(
      `${this.ACTIVE_KEY_PREFIX}${domain}`,
      data.operation_id
    );
    await multi.exec();
  }

  static async updateCoreReinstallStatus(operationId: string, update: Partial<StoredCoreReinstallData>): Promise<void> {
    const key = `${this.KEY_PREFIX}${operationId}`;
    const existing = await redis.get(key);
    if (!existing) throw new Error(`Core reinstall ${operationId} not found`);
    const stored: StoredCoreReinstallData = JSON.parse(existing);
    const updated = { ...stored, ...update };
    await redis.setex(key, this.TTL, JSON.stringify(updated));
    if (updated.status === 'completed' || updated.status === 'failed') {
      await redis.del(`${this.ACTIVE_KEY_PREFIX}${stored.domain}`);
    }
  }

  static async getCoreReinstall(operationId: string): Promise<StoredCoreReinstallData | null> {
    const data = await redis.get(`${this.KEY_PREFIX}${operationId}`);
    return data ? JSON.parse(data) : null;
  }

  static async getActiveCoreReinstall(domain: string): Promise<StoredCoreReinstallData | null> {
    const operationId = await redis.get(`${this.ACTIVE_KEY_PREFIX}${domain}`);
    if (!operationId) return null;
    return this.getCoreReinstall(operationId);
  }
}
