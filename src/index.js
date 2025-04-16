"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var express = require("express");
var cors = require("cors");
var morgan = require("morgan");
var dotenv_1 = require("dotenv");
var logger_1 = require("./services/logger");
var routes_1 = require("./routes");
var backups_1 = require("./routes/backups");
var webhook_secrets_1 = require("./routes/webhook-secrets");
// Load environment variables
(0, dotenv_1.config)({ path: '.env.local' });
// Log startup information
logger_1.logger.info({
    message: 'Starting WPFort AI server',
    nodeEnv: process.env.NODE_ENV,
    databaseConfigured: !!process.env.DATABASE_URL,
    apiKeyConfigured: !!process.env.WPFORT_API_KEY
}, {
    component: 'server',
    event: 'startup'
});
// Create Express app
var app = express();
// Middleware
app.use(cors());
app.use(express.json());
// Configure morgan to use our logger
app.use(morgan('dev', {
    stream: {
        write: function (message) {
            logger_1.logger.debug({
                message: message.trim()
            }, {
                component: 'server',
                event: 'http_request'
            });
        }
    }
}));
// Log all requests
app.use(function (req, res, next) {
    logger_1.logger.debug({
        message: 'Incoming request',
        method: req.method,
        url: req.url,
        ip: req.ip,
        userAgent: req.get('user-agent')
    }, {
        component: 'server',
        event: 'request_start'
    });
    next();
});
// API routes
app.use('/api', routes_1.default);
app.use('/api/backups', backups_1.default);
app.use('/api/webhook-secrets', webhook_secrets_1.default);
// Error handling middleware
app.use(function (err, req, res, next) {
    logger_1.logger.error({
        message: 'Unhandled error',
        error: err,
        method: req.method,
        url: req.url,
        ip: req.ip,
        statusCode: err.status || 500
    }, {
        component: 'server',
        event: 'unhandled_error'
    });
    res.status(err.status || 500).json({
        error: err.message || 'Internal Server Error'
    });
});
// Start server
var PORT = process.env.PORT || 3001;
app.listen(PORT, function () {
    logger_1.logger.info({
        message: 'Server started successfully',
        port: PORT,
        nodeEnv: process.env.NODE_ENV,
        pid: process.pid
    }, {
        component: 'server',
        event: 'server_started'
    });
});
