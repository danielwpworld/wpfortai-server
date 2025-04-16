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
// Add file to whitelist
router.post('/:domain', function (req, res) { return __awaiter(void 0, void 0, void 0, function () {
    var domain, _a, file_path, reason, added_by, website, api, error_1, errorDomain;
    return __generator(this, function (_b) {
        switch (_b.label) {
            case 0:
                _b.trys.push([0, 3, , 4]);
                domain = req.params.domain;
                _a = req.body, file_path = _a.file_path, reason = _a.reason, added_by = _a.added_by;
                logger_1.logger.debug({
                    message: 'Adding file to whitelist',
                    domain: domain,
                    filePath: file_path,
                    reason: reason,
                    addedBy: added_by
                }, {
                    component: 'whitelist-controller',
                    event: 'add_to_whitelist'
                });
                return [4 /*yield*/, (0, db_1.getWebsiteByDomain)(domain)];
            case 1:
                website = _b.sent();
                if (!website) {
                    return [2 /*return*/, res.status(404).json({ error: 'Website not found' })];
                }
                api = new wpsec_1.WPSecAPI(domain);
                // Add file to whitelist
                logger_1.logger.debug({
                    message: 'Sending whitelist request to WPSec API',
                    domain: domain,
                    filePath: file_path
                }, {
                    component: 'whitelist-controller',
                    event: 'whitelist_request'
                });
                return [4 /*yield*/, api.whitelistFile(file_path, reason, added_by)];
            case 2:
                _b.sent();
                logger_1.logger.info({
                    message: 'File added to whitelist successfully',
                    domain: domain,
                    filePath: file_path,
                    reason: reason,
                    addedBy: added_by
                }, {
                    component: 'whitelist-controller',
                    event: 'file_whitelisted'
                });
                res.json({ success: true });
                return [3 /*break*/, 4];
            case 3:
                error_1 = _b.sent();
                errorDomain = req.params.domain;
                logger_1.logger.error({
                    message: 'Error adding file to whitelist',
                    error: error_1,
                    domain: errorDomain,
                    filePath: req.body.file_path
                }, {
                    component: 'whitelist-controller',
                    event: 'whitelist_error'
                });
                res.status(500).json({ error: error_1.message });
                return [3 /*break*/, 4];
            case 4: return [2 /*return*/];
        }
    });
}); });
// Get whitelisted files
router.get('/:domain/files', function (req, res) { return __awaiter(void 0, void 0, void 0, function () {
    var domain, _a, include_details, verify_integrity, website, api, files, error_2, errorDomain;
    return __generator(this, function (_b) {
        switch (_b.label) {
            case 0:
                _b.trys.push([0, 3, , 4]);
                domain = req.params.domain;
                _a = req.query, include_details = _a.include_details, verify_integrity = _a.verify_integrity;
                logger_1.logger.debug({
                    message: 'Getting whitelisted files',
                    domain: domain,
                    includeDetails: include_details === '1',
                    verifyIntegrity: verify_integrity === '1'
                }, {
                    component: 'whitelist-controller',
                    event: 'get_whitelisted_files'
                });
                return [4 /*yield*/, (0, db_1.getWebsiteByDomain)(domain)];
            case 1:
                website = _b.sent();
                if (!website) {
                    return [2 /*return*/, res.status(404).json({ error: 'Website not found' })];
                }
                api = new wpsec_1.WPSecAPI(domain);
                // Get whitelisted files
                logger_1.logger.debug({
                    message: 'Fetching whitelisted files from WPSec API',
                    domain: domain
                }, {
                    component: 'whitelist-controller',
                    event: 'fetch_whitelisted_files'
                });
                return [4 /*yield*/, api.getWhitelistedFiles(include_details === '1', verify_integrity === '1')];
            case 2:
                files = _b.sent();
                logger_1.logger.info({
                    message: 'Whitelisted files retrieved',
                    domain: domain,
                    totalFiles: files.length,
                    includeDetails: include_details === '1',
                    verifyIntegrity: verify_integrity === '1'
                }, {
                    component: 'whitelist-controller',
                    event: 'files_retrieved'
                });
                res.json(files);
                return [3 /*break*/, 4];
            case 3:
                error_2 = _b.sent();
                errorDomain = req.params.domain;
                logger_1.logger.error({
                    message: 'Error getting whitelisted files',
                    error: error_2,
                    domain: errorDomain
                }, {
                    component: 'whitelist-controller',
                    event: 'get_files_error'
                });
                res.status(500).json({ error: error_2.message });
                return [3 /*break*/, 4];
            case 4: return [2 /*return*/];
        }
    });
}); });
// Remove file from whitelist
router.post('/:domain/remove', function (req, res) { return __awaiter(void 0, void 0, void 0, function () {
    var domain, file_path, website, api, error_3;
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
                // Remove file from whitelist
                return [4 /*yield*/, api.removeWhitelistedFile(file_path)];
            case 2:
                // Remove file from whitelist
                _a.sent();
                res.json({ success: true });
                return [3 /*break*/, 4];
            case 3:
                error_3 = _a.sent();
                console.error('Error removing file from whitelist:', error_3);
                res.status(500).json({ error: error_3.message });
                return [3 /*break*/, 4];
            case 4: return [2 /*return*/];
        }
    });
}); });
// Verify whitelist integrity
router.get('/:domain/verify', function (req, res) { return __awaiter(void 0, void 0, void 0, function () {
    var domain, website, api, result, error_4;
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
                return [4 /*yield*/, api.verifyWhitelistIntegrity()];
            case 2:
                result = _a.sent();
                res.json(result);
                return [3 /*break*/, 4];
            case 3:
                error_4 = _a.sent();
                console.error('Error verifying whitelist integrity:', error_4);
                res.status(500).json({ error: error_4.message });
                return [3 /*break*/, 4];
            case 4: return [2 /*return*/];
        }
    });
}); });
// Cleanup whitelist
router.post('/:domain/cleanup', function (req, res) { return __awaiter(void 0, void 0, void 0, function () {
    var domain, website, api, error_5;
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
                // Cleanup whitelist
                return [4 /*yield*/, api.cleanupWhitelist()];
            case 2:
                // Cleanup whitelist
                _a.sent();
                res.json({ success: true });
                return [3 /*break*/, 4];
            case 3:
                error_5 = _a.sent();
                console.error('Error cleaning up whitelist:', error_5);
                res.status(500).json({ error: error_5.message });
                return [3 /*break*/, 4];
            case 4: return [2 /*return*/];
        }
    });
}); });
exports.default = router;
