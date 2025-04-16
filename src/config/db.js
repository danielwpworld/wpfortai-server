"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g = Object.create((typeof Iterator === "function" ? Iterator : Object).prototype);
    return g.next = verb(0), g["throw"] = verb(1), g["return"] = verb(2), typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (g && (g = 0, op[0] && (_ = 0)), _) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getWebsiteByDomain = getWebsiteByDomain;
exports.createWebsiteScanResult = createWebsiteScanResult;
exports.createScanDetection = createScanDetection;
var pg_1 = require("pg");
var dotenv_1 = require("dotenv");
var logger_1 = require("../services/logger");
// Load environment variables
(0, dotenv_1.config)({ path: '.env.local' });
if (!process.env.DATABASE_URL) {
    throw new Error('DATABASE_URL environment variable is not set');
}
var pool = new pg_1.Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});
// Log database connection events
pool.on('connect', function () {
    logger_1.logger.info({
        message: 'New database connection established'
    }, {
        component: 'database',
        event: 'connection_established'
    });
});
pool.on('error', function (err) {
    logger_1.logger.error({
        message: 'Database connection error',
        error: err
    }, {
        component: 'database',
        event: 'connection_error'
    });
});
pool.on('remove', function () {
    logger_1.logger.debug({
        message: 'Database connection removed from pool'
    }, {
        component: 'database',
        event: 'connection_removed'
    });
});
function getWebsiteByDomain(domain) {
    return __awaiter(this, void 0, void 0, function () {
        var result, website, error_1;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    logger_1.logger.debug({
                        message: 'Looking up website by domain',
                        domain: domain
                    }, {
                        component: 'database',
                        event: 'website_lookup'
                    });
                    _a.label = 1;
                case 1:
                    _a.trys.push([1, 3, , 4]);
                    return [4 /*yield*/, pool.query('SELECT * FROM websites WHERE domain = $1', [domain])];
                case 2:
                    result = _a.sent();
                    website = result.rows[0] || null;
                    logger_1.logger.debug({
                        message: website ? 'Website found' : 'Website not found',
                        domain: domain,
                        found: !!website
                    }, {
                        component: 'database',
                        event: 'website_lookup_result'
                    });
                    return [2 /*return*/, website];
                case 3:
                    error_1 = _a.sent();
                    logger_1.logger.error({
                        message: 'Error looking up website',
                        error: error_1,
                        domain: domain
                    }, {
                        component: 'database',
                        event: 'website_lookup_error'
                    });
                    throw error_1;
                case 4: return [2 /*return*/];
            }
        });
    });
}
function createWebsiteScanResult(websiteId, scanData) {
    return __awaiter(this, void 0, void 0, function () {
        var error_2;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    _a.trys.push([0, 2, , 3]);
                    logger_1.logger.debug({
                        message: 'Creating website scan result',
                        websiteId: websiteId,
                        scanId: scanData.scan_id,
                        status: scanData.status
                    }, {
                        component: 'database',
                        event: 'create_scan_result'
                    });
                    return [4 /*yield*/, pool.query("INSERT INTO website_scans (\n        website_id, scan_id, infected_files_count, total_files_count,\n        started_at, completed_at, duration_seconds, status, error_message\n      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)", [
                            websiteId,
                            scanData.scan_id,
                            scanData.infected_files,
                            scanData.total_files,
                            scanData.started_at,
                            scanData.completed_at,
                            scanData.duration,
                            scanData.status || 'completed',
                            scanData.error_message
                        ])];
                case 1:
                    _a.sent();
                    logger_1.logger.info({
                        message: 'Website scan result created',
                        websiteId: websiteId,
                        scanId: scanData.scan_id,
                        status: scanData.status || 'completed'
                    }, {
                        component: 'database',
                        event: 'scan_result_created'
                    });
                    return [3 /*break*/, 3];
                case 2:
                    error_2 = _a.sent();
                    logger_1.logger.error({
                        message: 'Error creating website scan result',
                        error: error_2,
                        websiteId: websiteId,
                        scanId: scanData.scan_id
                    }, {
                        component: 'database',
                        event: 'scan_result_error'
                    });
                    throw error_2;
                case 3: return [2 /*return*/];
            }
        });
    });
}
function createScanDetection(websiteId, scanId, detection) {
    return __awaiter(this, void 0, void 0, function () {
        var error_3;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    _a.trys.push([0, 2, , 3]);
                    logger_1.logger.debug({
                        message: 'Creating scan detection',
                        websiteId: websiteId,
                        scanId: scanId,
                        filePath: detection.file_path,
                        detectionType: detection.detection_type,
                        severity: detection.severity
                    }, {
                        component: 'database',
                        event: 'create_detection'
                    });
                    return [4 /*yield*/, pool.query("INSERT INTO scan_detections (\n        website_id, scan_id, file_path, threat_score, confidence,\n        detection_type, severity, description, file_hash, file_size,\n        context_type, risk_level\n      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)", [
                            websiteId,
                            scanId,
                            detection.file_path,
                            detection.threat_score,
                            detection.confidence,
                            detection.detection_type,
                            detection.severity,
                            detection.description,
                            detection.file_hash,
                            detection.file_size,
                            detection.context_type,
                            detection.risk_level
                        ])];
                case 1:
                    _a.sent();
                    logger_1.logger.info({
                        message: 'Scan detection created',
                        websiteId: websiteId,
                        scanId: scanId,
                        filePath: detection.file_path,
                        severity: detection.severity
                    }, {
                        component: 'database',
                        event: 'detection_created'
                    });
                    return [3 /*break*/, 3];
                case 2:
                    error_3 = _a.sent();
                    logger_1.logger.error({
                        message: 'Error creating scan detection',
                        error: error_3,
                        websiteId: websiteId,
                        scanId: scanId,
                        filePath: detection.file_path
                    }, {
                        component: 'database',
                        event: 'detection_error'
                    });
                    throw error_3;
                case 3: return [2 /*return*/];
            }
        });
    });
}
exports.default = pool;
