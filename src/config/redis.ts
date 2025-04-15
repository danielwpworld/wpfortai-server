import Redis from 'ioredis';
import dotenv from 'dotenv';

dotenv.config({ path: '.env.local' });

const redis = new Redis({
  host: process.env.REDIS_SERVER?.split(':')[0] || '',
  port: parseInt(process.env.REDIS_SERVER?.split(':')[1] || '0'),
  username: process.env.REDIS_USERNAME,
  password: process.env.REDIS_PASSWORD,
});

export default redis;
