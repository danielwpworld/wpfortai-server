"use strict";
var __assign = (this && this.__assign) || function () {
    __assign = Object.assign || function(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p))
                t[p] = s[p];
        }
        return t;
    };
    return __assign.apply(this, arguments);
};
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
var express_1 = require("express");
var scan_store_1 = require("../services/scan-store");
var wpsec_1 = require("../services/wpsec");
var db_1 = require("../config/db");
var verify_webhook_1 = require("../middleware/verify-webhook");
var webhook_secrets_1 = require("../services/webhook-secrets");
var logger_1 = require("../services/logger");
var router = (0, express_1.Router)();
// Middleware to verify webhook signatures
router.use(function (req, res, next) { return __awaiter(void 0, void 0, void 0, function () {
    var scanId_1, scanData_1, website_1, secrets, error_1;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                _a.trys.push([0, 4, , 5]);
                logger_1.logger.debug({
                    message: 'Webhook request received',
                    path: req.path,
                    method: req.method,
                    body: req.body
                }, {
                    component: 'webhook-middleware'
                });
                scanId_1 = req.body.scan_id;
                if (!scanId_1) {
                    return [2 /*return*/, res.status(400).json({ error: 'scan_id is required' })];
                }
                logger_1.logger.debug({
                    message: 'Fetching scan data from Redis',
                    scanId: scanId_1
                }, {
                    component: 'webhook-middleware',
                    event: 'fetch_scan_start'
                });
                return [4 /*yield*/, scan_store_1.ScanStore.getScan(scanId_1)];
            case 1:
                scanData_1 = _a.sent();
                if (!scanData_1) {
                    logger_1.logger.warn({
                        message: 'Scan not found in Redis',
                        scanId: scanId_1
                    }, {
                        component: 'webhook-middleware',
                        event: 'scan_not_found'
                    });
                    return [2 /*return*/, res.status(404).json({ error: 'Scan not found' })];
                }
                logger_1.logger.debug({
                    message: 'Fetching website data',
                    domain: scanData_1.domain,
                    scanId: scanId_1
                }, {
                    component: 'webhook-middleware',
                    event: 'fetch_website_start'
                });
                return [4 /*yield*/, (0, db_1.getWebsiteByDomain)(scanData_1.domain)];
            case 2:
                website_1 = _a.sent();
                if (!website_1) {
                    logger_1.logger.warn({
                        message: 'Website not found',
                        domain: scanData_1.domain,
                        scanId: scanId_1
                    }, {
                        component: 'webhook-middleware',
                        event: 'website_not_found'
                    });
                    return [2 /*return*/, res.status(404).json({ error: 'Website not found' })];
                }
                logger_1.logger.debug({
                    message: 'Fetching webhook secrets',
                    websiteId: website_1.id,
                    domain: scanData_1.domain,
                    scanId: scanId_1
                }, {
                    component: 'webhook-middleware',
                    event: 'fetch_secrets_start'
                });
                return [4 /*yield*/, webhook_secrets_1.WebhookSecrets.getWebhookSecret(website_1.id)];
            case 3:
                secrets = _a.sent();
                if (!secrets) {
                    logger_1.logger.warn({
                        message: 'No webhook secret configured',
                        websiteId: website_1.id,
                        domain: scanData_1.domain,
                        scanId: scanId_1
                    }, {
                        component: 'webhook-middleware',
                        event: 'no_webhook_secret'
                    });
                    return [2 /*return*/, res.status(401).json({ error: 'No webhook secret configured' })];
                }
                logger_1.logger.debug({
                    message: 'Verifying webhook signature',
                    websiteId: website_1.id,
                    domain: scanData_1.domain,
                    scanId: scanId_1,
                    headers: {
                        signature: req.headers['x-wpfort-signature'],
                        timestamp: req.headers['x-wpfort-timestamp']
                    }
                }, {
                    component: 'webhook-middleware',
                    event: 'verify_signature_start'
                });
                // Try current secret first
                try {
                    (0, verify_webhook_1.verifyWebhook)(secrets.currentSecret)(req, res, function () {
                        logger_1.logger.debug({
                            message: 'Webhook signature verified with current secret',
                            websiteId: website_1.id,
                            domain: scanData_1.domain,
                            scanId: scanId_1
                        }, {
                            component: 'webhook-middleware',
                            event: 'signature_verified'
                        });
                        // Signature valid with current secret
                        next();
                    });
                }
                catch (e) {
                    // If old secret exists and current secret failed, try old secret
                    if (secrets.oldSecret) {
                        logger_1.logger.debug({
                            message: 'Trying old secret for verification',
                            websiteId: website_1.id,
                            domain: scanData_1.domain,
                            scanId: scanId_1
                        }, {
                            component: 'webhook-middleware',
                            event: 'try_old_secret'
                        });
                        try {
                            (0, verify_webhook_1.verifyWebhook)(secrets.oldSecret)(req, res, function () {
                                logger_1.logger.debug({
                                    message: 'Webhook signature verified with old secret',
                                    websiteId: website_1.id,
                                    domain: scanData_1.domain,
                                    scanId: scanId_1
                                }, {
                                    component: 'webhook-middleware',
                                    event: 'signature_verified_old'
                                });
                                // Signature valid with old secret
                                next();
                            });
                        }
                        catch (e) {
                            // Both secrets failed
                            return [2 /*return*/, res.status(401).json({ error: 'Invalid webhook signature' })];
                        }
                    }
                    else {
                        // No old secret to try
                        return [2 /*return*/, res.status(401).json({ error: 'Invalid webhook signature' })];
                    }
                }
                return [3 /*break*/, 5];
            case 4:
                error_1 = _a.sent();
                logger_1.logger.error({
                    message: 'Error in webhook verification middleware',
                    error: error_1,
                    scanId: req.body.scan_id
                }, {
                    component: 'webhook-middleware',
                    event: 'webhook_error'
                });
                res.status(500).json({ error: error_1.message });
                return [3 /*break*/, 5];
            case 5: return [2 /*return*/];
        }
    });
}); });
// Webhook for scan progress updates
router.post('/scan-progress', function (req, res) { return __awaiter(void 0, void 0, void 0, function () {
    var _a, scan_id, status_1, progress, scanData, existingScan, error_2;
    var _b;
    return __generator(this, function (_c) {
        switch (_c.label) {
            case 0:
                _c.trys.push([0, 4, , 5]);
                logger_1.logger.debug({
                    message: 'Processing scan progress webhook',
                    headers: req.headers,
                    body: req.body
                }, {
                    component: 'scan-progress-webhook',
                    event: 'process_start'
                });
                logger_1.logger.info({
                    message: 'Scan progress webhook received',
                    scanId: req.body.scan_id,
                    status: req.body.status,
                    progress: req.body.progress
                }, {
                    component: 'scan-progress-webhook'
                });
                _a = req.body, scan_id = _a.scan_id, status_1 = _a.status, progress = _a.progress;
                if (!scan_id) {
                    return [2 /*return*/, res.status(400).json({ error: 'scan_id is required' })];
                }
                return [4 /*yield*/, scan_store_1.ScanStore.getScan(scan_id)];
            case 1:
                scanData = _c.sent();
                if (!scanData) {
                    return [2 /*return*/, res.status(404).json({ error: 'Scan not found' })];
                }
                return [4 /*yield*/, scan_store_1.ScanStore.getScan(scan_id)];
            case 2:
                existingScan = _c.sent();
                if (!existingScan) {
                    return [2 /*return*/, res.status(404).json({ error: 'Scan not found' })];
                }
                return [4 /*yield*/, scan_store_1.ScanStore.updateScanStatus(scan_id, __assign(__assign({}, existingScan), { status: status_1 || existingScan.status, progress: (_b = progress !== null && progress !== void 0 ? progress : existingScan.progress) !== null && _b !== void 0 ? _b : 0 }))];
            case 3:
                _c.sent();
                res.json({ success: true });
                return [3 /*break*/, 5];
            case 4:
                error_2 = _c.sent();
                console.error('Error processing scan progress webhook:', error_2);
                res.status(500).json({ error: error_2.message });
                return [3 /*break*/, 5];
            case 5: return [2 /*return*/];
        }
    });
}); });
// Webhook for scan failed
router.post('/scan-failed', function (req, res) { return __awaiter(void 0, void 0, void 0, function () {
    var _a, scan_id, error_message, scanData, website, error_3;
    return __generator(this, function (_b) {
        switch (_b.label) {
            case 0:
                _b.trys.push([0, 5, , 6]);
                _a = req.body, scan_id = _a.scan_id, error_message = _a.error_message;
                if (!scan_id) {
                    return [2 /*return*/, res.status(400).json({ error: 'scan_id is required' })];
                }
                return [4 /*yield*/, scan_store_1.ScanStore.getScan(scan_id)];
            case 1:
                scanData = _b.sent();
                if (!scanData) {
                    return [2 /*return*/, res.status(404).json({ error: 'Scan not found' })];
                }
                return [4 /*yield*/, (0, db_1.getWebsiteByDomain)(scanData.domain)];
            case 2:
                website = _b.sent();
                if (!website) {
                    return [2 /*return*/, res.status(404).json({ error: 'Website not found' })];
                }
                // Update scan status in Redis
                return [4 /*yield*/, scan_store_1.ScanStore.updateScanStatus(scan_id, __assign(__assign({}, scanData), { status: 'failed', error: error_message }))];
            case 3:
                // Update scan status in Redis
                _b.sent();
                // Store scan failure in database
                return [4 /*yield*/, (0, db_1.createWebsiteScanResult)(website.id, {
                        scan_id: scan_id,
                        infected_files: 0,
                        total_files: 0,
                        started_at: new Date(scanData.started_at || Date.now()),
                        completed_at: new Date(),
                        duration: 0,
                        status: 'failed',
                        error_message: error_message
                    })];
            case 4:
                // Store scan failure in database
                _b.sent();
                res.json({ success: true });
                return [3 /*break*/, 6];
            case 5:
                error_3 = _b.sent();
                console.error('Error processing scan failed webhook:', error_3);
                res.status(500).json({ error: error_3.message });
                return [3 /*break*/, 6];
            case 6: return [2 /*return*/];
        }
    });
}); });
// Webhook for scan completion
router.post('/scan-complete', function (req, res) { return __awaiter(void 0, void 0, void 0, function () {
    var scan_id, scanData, website, api, results, _i, _a, file, _b, _c, detection, error_4;
    return __generator(this, function (_d) {
        switch (_d.label) {
            case 0:
                _d.trys.push([0, 11, , 12]);
                scan_id = req.body.scan_id;
                if (!scan_id) {
                    return [2 /*return*/, res.status(400).json({ error: 'scan_id is required' })];
                }
                return [4 /*yield*/, scan_store_1.ScanStore.getScan(scan_id)];
            case 1:
                scanData = _d.sent();
                if (!scanData) {
                    return [2 /*return*/, res.status(404).json({ error: 'Scan not found' })];
                }
                return [4 /*yield*/, (0, db_1.getWebsiteByDomain)(scanData.domain)];
            case 2:
                website = _d.sent();
                if (!website) {
                    return [2 /*return*/, res.status(404).json({ error: 'Website not found' })];
                }
                api = new wpsec_1.WPSecAPI(scanData.domain);
                return [4 /*yield*/, api.getScanResults(scan_id)];
            case 3:
                results = _d.sent();
                // Store scan results in database
                return [4 /*yield*/, (0, db_1.createWebsiteScanResult)(website.id, {
                        scan_id: scan_id,
                        infected_files: parseInt(results.infected_count),
                        total_files: parseInt(results.total_files_scanned),
                        started_at: new Date(results.started_at),
                        completed_at: new Date(results.completed_at),
                        duration: parseInt(results.duration)
                    })];
            case 4:
                // Store scan results in database
                _d.sent();
                _i = 0, _a = results.infected_files;
                _d.label = 5;
            case 5:
                if (!(_i < _a.length)) return [3 /*break*/, 10];
                file = _a[_i];
                _b = 0, _c = file.detections;
                _d.label = 6;
            case 6:
                if (!(_b < _c.length)) return [3 /*break*/, 9];
                detection = _c[_b];
                return [4 /*yield*/, (0, db_1.createScanDetection)(website.id, scan_id, {
                        file_path: file.file_path,
                        threat_score: file.threat_score,
                        confidence: file.confidence,
                        detection_type: detection.type,
                        severity: detection.severity,
                        description: detection.description,
                        file_hash: detection.file_hash,
                        file_size: file.file_size,
                        context_type: file.context.type,
                        risk_level: file.context.risk_level
                    })];
            case 7:
                _d.sent();
                _d.label = 8;
            case 8:
                _b++;
                return [3 /*break*/, 6];
            case 9:
                _i++;
                return [3 /*break*/, 5];
            case 10:
                res.json({ success: true });
                return [3 /*break*/, 12];
            case 11:
                error_4 = _d.sent();
                console.error('Error processing scan completion webhook:', error_4);
                res.status(500).json({ error: error_4.message });
                return [3 /*break*/, 12];
            case 12: return [2 /*return*/];
        }
    });
}); });
exports.default = router;
