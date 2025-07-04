import fs from 'fs';
import path from 'path';

// Simple debug logger that writes to a file
export const logToFile = (message: string, data?: any): void => {
  const timestamp = new Date().toISOString();
  const logDir = path.join(process.cwd(), 'logs');
  const logFile = path.join(logDir, 'email-debug.log');
  
  // Create logs directory if it doesn't exist
  if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir, { recursive: true });
  }
  
  // Format the log message
  let logMessage = `[${timestamp}] ${message}`;
  if (data !== undefined) {
    logMessage += `\n${JSON.stringify(data, null, 2)}`;
  }
  logMessage += '\n';
  
  // Append to log file
  fs.appendFileSync(logFile, logMessage);
};
