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
var express_1 = require("express");
var wpsec_1 = require("../services/wpsec");
var scan_store_1 = require("../services/scan-store");
var db_1 = require("../config/db");
var logger_1 = require("../services/logger");
var router = (0, express_1.Router)();
// Start a new scan
router.post('/:domain/start', function (req, res) { return __awaiter(void 0, void 0, void 0, function () {
    var domain, website, activeScan, api, scanData, error_1, errorDomain;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                _a.trys.push([0, 4, , 5]);
                domain = req.params.domain;
                logger_1.logger.debug({
                    message: 'Starting new scan',
                    domain: domain,
                    body: req.body
                }, {
                    component: 'scan-controller',
                    event: 'scan_start_request'
                });
                return [4 /*yield*/, (0, db_1.getWebsiteByDomain)(domain)];
            case 1:
                website = _a.sent();
                if (!website) {
                    return [2 /*return*/, res.status(404).json({ error: 'Website not found' })];
                }
                // Check if there's already an active scan
                logger_1.logger.debug({
                    message: 'Checking for active scan',
                    domain: domain
                }, {
                    component: 'scan-controller',
                    event: 'check_active_scan'
                });
                return [4 /*yield*/, scan_store_1.ScanStore.getActiveScan(domain)];
            case 2:
                activeScan = _a.sent();
                if (activeScan) {
                    logger_1.logger.info({
                        message: 'Active scan already exists',
                        domain: domain,
                        activeScanId: activeScan.scan_id
                    }, {
                        component: 'scan-controller',
                        event: 'scan_already_active'
                    });
                    return [2 /*return*/, res.status(409).json({ error: 'A scan is already in progress', scan_id: activeScan.scan_id })];
                }
                api = new wpsec_1.WPSecAPI(domain);
                // Start scan
                logger_1.logger.debug({
                    message: 'Initiating scan with WPSec API',
                    domain: domain
                }, {
                    component: 'scan-controller',
                    event: 'wpsec_scan_start'
                });
                return [4 /*yield*/, api.startScan()];
            case 3:
                scanData = _a.sent();
                logger_1.logger.info({
                    message: 'Scan started successfully',
                    domain: domain,
                    scanId: scanData.scan_id
                }, {
                    component: 'scan-controller',
                    event: 'scan_started'
                });
                res.json(scanData);
                return [3 /*break*/, 5];
            case 4:
                error_1 = _a.sent();
                errorDomain = req.params.domain;
                logger_1.logger.error({
                    message: 'Error starting scan',
                    error: error_1,
                    domain: errorDomain
                }, {
                    component: 'scan-controller',
                    event: 'scan_start_error'
                });
                res.status(500).json({ error: error_1.message });
                return [3 /*break*/, 5];
            case 5: return [2 /*return*/];
        }
    });
}); });
// Get scan status
router.get('/:domain/status/:scanId', function (req, res) { return __awaiter(void 0, void 0, void 0, function () {
    var _a, domain, scanId, website, api, status_1, error_2;
    return __generator(this, function (_b) {
        switch (_b.label) {
            case 0:
                _b.trys.push([0, 3, , 4]);
                _a = req.params, domain = _a.domain, scanId = _a.scanId;
                logger_1.logger.debug({
                    message: 'Getting scan status',
                    domain: domain,
                    scanId: scanId
                }, {
                    component: 'scan-controller',
                    event: 'get_scan_status'
                });
                return [4 /*yield*/, (0, db_1.getWebsiteByDomain)(domain)];
            case 1:
                website = _b.sent();
                if (!website) {
                    return [2 /*return*/, res.status(404).json({ error: 'Website not found' })];
                }
                api = new wpsec_1.WPSecAPI(domain);
                // Get scan status
                logger_1.logger.debug({
                    message: 'Fetching scan status from WPSec API',
                    domain: domain,
                    scanId: scanId
                }, {
                    component: 'scan-controller',
                    event: 'fetch_scan_status'
                });
                return [4 /*yield*/, api.getScanStatus(scanId)];
            case 2:
                status_1 = _b.sent();
                logger_1.logger.info({
                    message: 'Scan status retrieved',
                    domain: domain,
                    scanId: scanId,
                    status: status_1.status,
                    progress: status_1.progress
                }, {
                    component: 'scan-controller',
                    event: 'scan_status_retrieved'
                });
                res.json(status_1);
                return [3 /*break*/, 4];
            case 3:
                error_2 = _b.sent();
                console.error('Error getting scan status:', error_2);
                res.status(500).json({ error: error_2.message });
                return [3 /*break*/, 4];
            case 4: return [2 /*return*/];
        }
    });
}); });
// Get scan results
router.get('/:domain/results/:scanId', function (req, res) { return __awaiter(void 0, void 0, void 0, function () {
    var _a, domain, scanId, website, api, results, error_3;
    var _b, _c;
    return __generator(this, function (_d) {
        switch (_d.label) {
            case 0:
                _d.trys.push([0, 3, , 4]);
                _a = req.params, domain = _a.domain, scanId = _a.scanId;
                return [4 /*yield*/, (0, db_1.getWebsiteByDomain)(domain)];
            case 1:
                website = _d.sent();
                if (!website) {
                    return [2 /*return*/, res.status(404).json({ error: 'Website not found' })];
                }
                api = new wpsec_1.WPSecAPI(domain);
                // Get scan results
                logger_1.logger.debug({
                    message: 'Fetching scan results from WPSec API',
                    domain: domain,
                    scanId: scanId
                }, {
                    component: 'scan-controller',
                    event: 'fetch_scan_results'
                });
                return [4 /*yield*/, api.getScanResults(scanId)];
            case 2:
                results = _d.sent();
                logger_1.logger.info({
                    message: 'Scan results retrieved',
                    domain: domain,
                    scanId: scanId,
                    totalIssues: ((_b = results.issues) === null || _b === void 0 ? void 0 : _b.length) || 0,
                    totalFiles: ((_c = results.files) === null || _c === void 0 ? void 0 : _c.length) || 0
                }, {
                    component: 'scan-controller',
                    event: 'scan_results_retrieved'
                });
                res.json(results);
                return [3 /*break*/, 4];
            case 3:
                error_3 = _d.sent();
                console.error('Error getting scan results:', error_3);
                res.status(500).json({ error: error_3.message });
                return [3 /*break*/, 4];
            case 4: return [2 /*return*/];
        }
    });
}); });
// Get active scan for a domain
router.get('/:domain/active', function (req, res) { return __awaiter(void 0, void 0, void 0, function () {
    var domain, website, activeScan, error_4;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                _a.trys.push([0, 3, , 4]);
                domain = req.params.domain;
                return [4 /*yield*/, (0, db_1.getWebsiteByDomain)(domain)];
            case 1:
                website = _a.sent();
                if (!website) {
                    return [2 /*return*/, res.status(404).json({ error: 'Website not found' })];
                }
                // Get active scan
                logger_1.logger.debug({
                    message: 'Checking for active scan',
                    domain: domain
                }, {
                    component: 'scan-controller',
                    event: 'check_active_scan'
                });
                return [4 /*yield*/, scan_store_1.ScanStore.getActiveScan(domain)];
            case 2:
                activeScan = _a.sent();
                if (!activeScan) {
                    logger_1.logger.info({
                        message: 'No active scan found',
                        domain: domain
                    }, {
                        component: 'scan-controller',
                        event: 'no_active_scan'
                    });
                    return [2 /*return*/, res.status(404).json({ error: 'No active scan found' })];
                }
                res.json(activeScan);
                return [3 /*break*/, 4];
            case 3:
                error_4 = _a.sent();
                console.error('Error getting active scan:', error_4);
                res.status(500).json({ error: error_4.message });
                return [3 /*break*/, 4];
            case 4: return [2 /*return*/];
        }
    });
}); });
// Quarantine a single file
router.post('/:domain/quarantine', function (req, res) { return __awaiter(void 0, void 0, void 0, function () {
    var domain, file_path, website, api, result, error_5;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                _a.trys.push([0, 3, , 4]);
                domain = req.params.domain;
                file_path = req.body.file_path;
                return [4 /*yield*/, (0, db_1.getWebsiteByDomain)(domain)];
            case 1:
                website = _a.sent();
                if (!website) {
                    return [2 /*return*/, res.status(404).json({ error: 'Website not found' })];
                }
                api = new wpsec_1.WPSecAPI(domain);
                // Quarantine file
                logger_1.logger.debug({
                    message: 'Quarantining file',
                    domain: domain,
                    filePath: file_path
                }, {
                    component: 'scan-controller',
                    event: 'quarantine_file'
                });
                return [4 /*yield*/, api.quarantineFile(file_path)];
            case 2:
                result = _a.sent();
                logger_1.logger.info({
                    message: 'File quarantined successfully',
                    domain: domain,
                    filePath: file_path,
                    quarantineId: result.quarantine_id
                }, {
                    component: 'scan-controller',
                    event: 'file_quarantined'
                });
                res.json(result);
                return [3 /*break*/, 4];
            case 3:
                error_5 = _a.sent();
                console.error('Error quarantining file:', error_5);
                res.status(500).json({ error: error_5.message });
                return [3 /*break*/, 4];
            case 4: return [2 /*return*/];
        }
    });
}); });
// Get quarantined files
router.get('/:domain/quarantine', function (req, res) { return __awaiter(void 0, void 0, void 0, function () {
    var domain, website, api, files, error_6;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                _a.trys.push([0, 3, , 4]);
                domain = req.params.domain;
                return [4 /*yield*/, (0, db_1.getWebsiteByDomain)(domain)];
            case 1:
                website = _a.sent();
                if (!website) {
                    return [2 /*return*/, res.status(404).json({ error: 'Website not found' })];
                }
                api = new wpsec_1.WPSecAPI(domain);
                return [4 /*yield*/, api.getQuarantinedFiles()];
            case 2:
                files = _a.sent();
                res.json(files);
                return [3 /*break*/, 4];
            case 3:
                error_6 = _a.sent();
                console.error('Error getting quarantined files:', error_6);
                res.status(500).json({ error: error_6.message });
                return [3 /*break*/, 4];
            case 4: return [2 /*return*/];
        }
    });
}); });
// Restore quarantined file
router.post('/:domain/quarantine/restore', function (req, res) { return __awaiter(void 0, void 0, void 0, function () {
    var domain, quarantine_id, website, api, result, error_7;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                _a.trys.push([0, 3, , 4]);
                domain = req.params.domain;
                quarantine_id = req.body.quarantine_id;
                return [4 /*yield*/, (0, db_1.getWebsiteByDomain)(domain)];
            case 1:
                website = _a.sent();
                if (!website) {
                    return [2 /*return*/, res.status(404).json({ error: 'Website not found' })];
                }
                api = new wpsec_1.WPSecAPI(domain);
                return [4 /*yield*/, api.restoreQuarantinedFile(quarantine_id)];
            case 2:
                result = _a.sent();
                res.json(result);
                return [3 /*break*/, 4];
            case 3:
                error_7 = _a.sent();
                console.error('Error restoring quarantined file:', error_7);
                res.status(500).json({ error: error_7.message });
                return [3 /*break*/, 4];
            case 4: return [2 /*return*/];
        }
    });
}); });
// Batch delete/quarantine files
router.post('/:domain/quarantine/batch', function (req, res) { return __awaiter(void 0, void 0, void 0, function () {
    var domain, _a, operation, files, website, api, result, error_8;
    return __generator(this, function (_b) {
        switch (_b.label) {
            case 0:
                _b.trys.push([0, 3, , 4]);
                domain = req.params.domain;
                _a = req.body, operation = _a.operation, files = _a.files;
                // Validate operation
                if (!['delete', 'quarantine'].includes(operation)) {
                    return [2 /*return*/, res.status(400).json({ error: 'Invalid operation. Must be either "delete" or "quarantine".' })];
                }
                return [4 /*yield*/, (0, db_1.getWebsiteByDomain)(domain)];
            case 1:
                website = _b.sent();
                if (!website) {
                    return [2 /*return*/, res.status(404).json({ error: 'Website not found' })];
                }
                api = new wpsec_1.WPSecAPI(domain);
                return [4 /*yield*/, api.batchFileOperation(operation, files)];
            case 2:
                result = _b.sent();
                res.json(result);
                return [3 /*break*/, 4];
            case 3:
                error_8 = _b.sent();
                console.error('Error processing batch operation:', error_8);
                res.status(500).json({ error: error_8.message });
                return [3 /*break*/, 4];
            case 4: return [2 /*return*/];
        }
    });
}); });
exports.default = router;
