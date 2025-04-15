import Redis from 'ioredis';

const redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');

// Helper functions for managing active scans
export const getActiveScan = async (domain: string) => {
  const data = await redis.get(`active_scan:${domain}`);
  return data ? JSON.parse(data) : null;
};

export const setActiveScan = async (domain: string, data: any) => {
  await redis.set(`active_scan:${domain}`, JSON.stringify(data));
};

export default redis;
