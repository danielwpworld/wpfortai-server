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
var db_1 = require("../config/db");
var logger_1 = require("../services/logger");
var router = (0, express_1.Router)();
// Start a backup
router.post('/:domain/start', function (req, res) { return __awaiter(void 0, void 0, void 0, function () {
    var domain, _a, type, incremental, website, api, result, error_1, errorDomain;
    return __generator(this, function (_b) {
        switch (_b.label) {
            case 0:
                _b.trys.push([0, 3, , 4]);
                domain = req.params.domain;
                _a = req.body, type = _a.type, incremental = _a.incremental;
                logger_1.logger.debug({
                    message: 'Starting new backup',
                    domain: domain,
                    type: type,
                    incremental: incremental
                }, {
                    component: 'backup-controller',
                    event: 'start_backup'
                });
                if (!type) {
                    logger_1.logger.warn({
                        message: 'Missing backup type',
                        domain: domain
                    }, {
                        component: 'backup-controller',
                        event: 'missing_type'
                    });
                    return [2 /*return*/, res.status(400).json({ error: 'type is required' })];
                }
                return [4 /*yield*/, (0, db_1.getWebsiteByDomain)(domain)];
            case 1:
                website = _b.sent();
                if (!website) {
                    return [2 /*return*/, res.status(404).json({ error: 'Website not found' })];
                }
                api = new wpsec_1.WPSecAPI(domain);
                // Start backup
                logger_1.logger.debug({
                    message: 'Initiating backup with WPSec API',
                    domain: domain,
                    type: type,
                    incremental: incremental
                }, {
                    component: 'backup-controller',
                    event: 'initiate_backup'
                });
                return [4 /*yield*/, api.startBackup(type, incremental)];
            case 2:
                result = _b.sent();
                logger_1.logger.info({
                    message: 'Backup started successfully',
                    domain: domain,
                    backupId: result.backup_id,
                    type: type,
                    incremental: incremental
                }, {
                    component: 'backup-controller',
                    event: 'backup_started'
                });
                res.json(result);
                return [3 /*break*/, 4];
            case 3:
                error_1 = _b.sent();
                errorDomain = req.params.domain;
                logger_1.logger.error({
                    message: 'Error starting backup',
                    error: error_1,
                    domain: errorDomain,
                    type: req.body.type,
                    incremental: req.body.incremental
                }, {
                    component: 'backup-controller',
                    event: 'backup_start_error'
                });
                res.status(500).json({ error: error_1.message });
                return [3 /*break*/, 4];
            case 4: return [2 /*return*/];
        }
    });
}); });
// Get backup status
router.get('/:domain/status/:backupId', function (req, res) { return __awaiter(void 0, void 0, void 0, function () {
    var _a, domain, backupId, website, api, status_1, error_2, errorDomain;
    return __generator(this, function (_b) {
        switch (_b.label) {
            case 0:
                _b.trys.push([0, 3, , 4]);
                _a = req.params, domain = _a.domain, backupId = _a.backupId;
                logger_1.logger.debug({
                    message: 'Getting backup status',
                    domain: domain,
                    backupId: backupId
                }, {
                    component: 'backup-controller',
                    event: 'get_backup_status'
                });
                return [4 /*yield*/, (0, db_1.getWebsiteByDomain)(domain)];
            case 1:
                website = _b.sent();
                if (!website) {
                    return [2 /*return*/, res.status(404).json({ error: 'Website not found' })];
                }
                api = new wpsec_1.WPSecAPI(domain);
                // Get backup status
                logger_1.logger.debug({
                    message: 'Fetching backup status from WPSec API',
                    domain: domain,
                    backupId: backupId
                }, {
                    component: 'backup-controller',
                    event: 'fetch_backup_status'
                });
                return [4 /*yield*/, api.getBackupStatus(backupId)];
            case 2:
                status_1 = _b.sent();
                logger_1.logger.info({
                    message: 'Backup status retrieved',
                    domain: domain,
                    backupId: backupId,
                    status: status_1.status,
                    progress: status_1.progress,
                    size: status_1.size
                }, {
                    component: 'backup-controller',
                    event: 'backup_status_retrieved'
                });
                res.json(status_1);
                return [3 /*break*/, 4];
            case 3:
                error_2 = _b.sent();
                errorDomain = req.params.domain;
                logger_1.logger.error({
                    message: 'Error getting backup status',
                    error: error_2,
                    domain: errorDomain,
                    backupId: req.params.backupId
                }, {
                    component: 'backup-controller',
                    event: 'backup_status_error'
                });
                res.status(500).json({ error: error_2.message });
                return [3 /*break*/, 4];
            case 4: return [2 /*return*/];
        }
    });
}); });
// List backups
router.get('/:domain/list', function (req, res) { return __awaiter(void 0, void 0, void 0, function () {
    var domain, website, api, backups, error_3;
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
                return [4 /*yield*/, api.listBackups()];
            case 2:
                backups = _a.sent();
                res.json(backups);
                return [3 /*break*/, 4];
            case 3:
                error_3 = _a.sent();
                console.error('Error listing backups:', error_3);
                res.status(500).json({ error: error_3.message });
                return [3 /*break*/, 4];
            case 4: return [2 /*return*/];
        }
    });
}); });
// Restore backup
router.post('/:domain/restore/:backupId', function (req, res) { return __awaiter(void 0, void 0, void 0, function () {
    var _a, domain, backupId, website, api, result, error_4;
    return __generator(this, function (_b) {
        switch (_b.label) {
            case 0:
                _b.trys.push([0, 3, , 4]);
                _a = req.params, domain = _a.domain, backupId = _a.backupId;
                return [4 /*yield*/, (0, db_1.getWebsiteByDomain)(domain)];
            case 1:
                website = _b.sent();
                if (!website) {
                    return [2 /*return*/, res.status(404).json({ error: 'Website not found' })];
                }
                api = new wpsec_1.WPSecAPI(domain);
                return [4 /*yield*/, api.restoreBackup(backupId)];
            case 2:
                result = _b.sent();
                res.json(result);
                return [3 /*break*/, 4];
            case 3:
                error_4 = _b.sent();
                console.error('Error restoring backup:', error_4);
                res.status(500).json({ error: error_4.message });
                return [3 /*break*/, 4];
            case 4: return [2 /*return*/];
        }
    });
}); });
// Get restore status
router.get('/:domain/restore/:restoreId/status', function (req, res) { return __awaiter(void 0, void 0, void 0, function () {
    var _a, domain, restoreId, website, api, status_2, error_5;
    return __generator(this, function (_b) {
        switch (_b.label) {
            case 0:
                _b.trys.push([0, 3, , 4]);
                _a = req.params, domain = _a.domain, restoreId = _a.restoreId;
                return [4 /*yield*/, (0, db_1.getWebsiteByDomain)(domain)];
            case 1:
                website = _b.sent();
                if (!website) {
                    return [2 /*return*/, res.status(404).json({ error: 'Website not found' })];
                }
                api = new wpsec_1.WPSecAPI(domain);
                return [4 /*yield*/, api.getRestoreStatus(restoreId)];
            case 2:
                status_2 = _b.sent();
                res.json(status_2);
                return [3 /*break*/, 4];
            case 3:
                error_5 = _b.sent();
                console.error('Error getting restore status:', error_5);
                res.status(500).json({ error: error_5.message });
                return [3 /*break*/, 4];
            case 4: return [2 /*return*/];
        }
    });
}); });
exports.default = router;
