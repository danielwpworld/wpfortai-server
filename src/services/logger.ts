import { getLokiLogger } from '@miketako3/cloki';

class Logger {
  private cloki?: ReturnType<typeof getLokiLogger>;
  private defaultLabels: Record<string, string>;

  constructor() {
    this.defaultLabels = {
      app: 'wpfort',
      environment: process.env.NODE_ENV || 'development',
      service: 'api'
    };
  }

  private initCloki() {
    if (!this.cloki) {
      // Remove https:// from the host
      const lokiHost = process.env.GRAFANA_LOKI_HOST!.replace(/^https?:\/\//, '');
      this.cloki = getLokiLogger({
        lokiHost,
        lokiUser: process.env.GRAFANA_LOKI_USER!,
        lokiToken: process.env.GRAFANA_LOKI_TOKEN!
      });
    }
    return this.cloki;
  }

  async info(data: { message: string; [key: string]: any }, labels: Record<string, string> = {}) {
    await this.initCloki().info({ ...data }, { ...this.defaultLabels, ...labels });
  }

  async error(data: { message: string; error?: Error; [key: string]: any }, labels: Record<string, string> = {}) {
    const errorData = {
      ...data,
      stack: data.error?.stack,
      errorName: data.error?.name,
      errorMessage: data.error?.message
    };
    await this.initCloki().error(errorData, { ...this.defaultLabels, ...labels });
  }

  async warn(data: { message: string; [key: string]: any }, labels: Record<string, string> = {}) {
    await this.initCloki().warn({ ...data }, { ...this.defaultLabels, ...labels });
  }

  async debug(data: { message: string; [key: string]: any }, labels: Record<string, string> = {}) {
    const logLevel = (process.env.LOG_LEVEL || 'info').toLowerCase();
    if (logLevel === 'debug') {
      await this.initCloki().debug({ ...data }, { ...this.defaultLabels, ...labels });
    }
  }
}

export const logger = new Logger();
