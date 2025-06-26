import Pusher from 'pusher';
import { config } from 'dotenv';
import { logger } from './logger';

// Load environment variables
config({ path: '.env.local' });

// Initialize Pusher client
const pusher = new Pusher({
  appId: process.env.PUSHER_APP_ID || '',
  key: process.env.PUSHER_KEY || '',
  secret: process.env.PUSHER_SECRET || '',
  cluster: process.env.PUSHER_CLUSTER || 'ap1',
  useTLS: true
});

/**
 * Broadcast an event to a specific website channel
 * @param websiteId - UUID of the website
 * @param eventName - Name of the event
 * @param data - Data to broadcast
 */
export const broadcastToWebsite = async (websiteId: string, eventName: string, data: any): Promise<void> => {
  try {
    const channelName = `${websiteId}`;
    
    logger.debug({
      message: 'Broadcasting event to website channel',
      websiteId,
      channelName,
      eventName
    }, {
      component: 'pusher-service',
      event: 'broadcast_event'
    });
    
    await pusher.trigger(channelName, eventName, data);
    
    logger.debug({
      message: 'Successfully broadcast event',
      websiteId,
      channelName,
      eventName
    }, {
      component: 'pusher-service',
      event: 'broadcast_success'
    });
  } catch (error: unknown) {
    const errorObj = error instanceof Error ? error : new Error(String(error));
    
    logger.error({
      message: 'Failed to broadcast event',
      websiteId,
      eventName,
      error: errorObj
    }, {
      component: 'pusher-service',
      event: 'broadcast_error'
    });
    
    // Ensure we're throwing an Error object
    if (error instanceof Error) {
      throw error;
    } else {
      throw new Error(String(error));
    }
  }
};
