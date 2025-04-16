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
// Get site information
router.get('/:domain/info', function (req, res) { return __awaiter(void 0, void 0, void 0, function () {
    var domain, website, api, info, error_1, errorDomain;
    var _a, _b;
    return __generator(this, function (_c) {
        switch (_c.label) {
            case 0:
                _c.trys.push([0, 3, , 4]);
                domain = req.params.domain;
                logger_1.logger.debug({
                    message: 'Getting site information',
                    domain: domain
                }, {
                    component: 'sites-controller',
                    event: 'get_site_info'
                });
                return [4 /*yield*/, (0, db_1.getWebsiteByDomain)(domain)];
            case 1:
                website = _c.sent();
                if (!website) {
                    return [2 /*return*/, res.status(404).json({ error: 'Website not found' })];
                }
                api = new wpsec_1.WPSecAPI(domain);
                // Get site info
                logger_1.logger.debug({
                    message: 'Fetching site info from WPSec API',
                    domain: domain
                }, {
                    component: 'sites-controller',
                    event: 'fetch_site_info'
                });
                return [4 /*yield*/, api.getSiteInfo()];
            case 2:
                info = _c.sent();
                logger_1.logger.info({
                    message: 'Site information retrieved',
                    domain: domain,
                    wpVersion: info.wp_version,
                    totalPlugins: ((_a = info.plugins) === null || _a === void 0 ? void 0 : _a.length) || 0,
                    totalThemes: ((_b = info.themes) === null || _b === void 0 ? void 0 : _b.length) || 0
                }, {
                    component: 'sites-controller',
                    event: 'site_info_retrieved'
                });
                res.json(info);
                return [3 /*break*/, 4];
            case 3:
                error_1 = _c.sent();
                errorDomain = req.params.domain;
                logger_1.logger.error({
                    message: 'Error getting site info',
                    error: error_1,
                    domain: errorDomain
                }, {
                    component: 'sites-controller',
                    event: 'site_info_error'
                });
                res.status(500).json({ error: error_1.message });
                return [3 /*break*/, 4];
            case 4: return [2 /*return*/];
        }
    });
}); });
// Get site vulnerabilities
router.get('/:domain/vulnerabilities', function (req, res) { return __awaiter(void 0, void 0, void 0, function () {
    var domain, website, api, vulnerabilities, error_2;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                _a.trys.push([0, 3, , 4]);
                domain = req.params.domain;
                logger_1.logger.debug({
                    message: 'Getting site vulnerabilities',
                    domain: domain
                }, {
                    component: 'sites-controller',
                    event: 'get_vulnerabilities'
                });
                return [4 /*yield*/, (0, db_1.getWebsiteByDomain)(domain)];
            case 1:
                website = _a.sent();
                if (!website) {
                    return [2 /*return*/, res.status(404).json({ error: 'Website not found' })];
                }
                api = new wpsec_1.WPSecAPI(domain);
                // Get vulnerabilities
                logger_1.logger.debug({
                    message: 'Fetching vulnerabilities from WPSec API',
                    domain: domain
                }, {
                    component: 'sites-controller',
                    event: 'fetch_vulnerabilities'
                });
                return [4 /*yield*/, api.getVulnerabilities()];
            case 2:
                vulnerabilities = _a.sent();
                logger_1.logger.info({
                    message: 'Vulnerabilities retrieved',
                    domain: domain,
                    totalVulnerabilities: vulnerabilities.length || 0,
                    severity: {
                        high: vulnerabilities.filter(function (v) { return v.severity === 'high'; }).length || 0,
                        medium: vulnerabilities.filter(function (v) { return v.severity === 'medium'; }).length || 0,
                        low: vulnerabilities.filter(function (v) { return v.severity === 'low'; }).length || 0
                    }
                }, {
                    component: 'sites-controller',
                    event: 'vulnerabilities_retrieved'
                });
                res.json(vulnerabilities);
                return [3 /*break*/, 4];
            case 3:
                error_2 = _a.sent();
                console.error('Error getting vulnerabilities:', error_2);
                res.status(500).json({ error: error_2.message });
                return [3 /*break*/, 4];
            case 4: return [2 /*return*/];
        }
    });
}); });
// Check core integrity
router.get('/:domain/core-check', function (req, res) { return __awaiter(void 0, void 0, void 0, function () {
    var domain, website, api, result, error_3, errorDomain;
    var _a, _b;
    return __generator(this, function (_c) {
        switch (_c.label) {
            case 0:
                _c.trys.push([0, 3, , 4]);
                domain = req.params.domain;
                logger_1.logger.debug({
                    message: 'Starting core integrity check',
                    domain: domain
                }, {
                    component: 'sites-controller',
                    event: 'start_core_check'
                });
                return [4 /*yield*/, (0, db_1.getWebsiteByDomain)(domain)];
            case 1:
                website = _c.sent();
                if (!website) {
                    return [2 /*return*/, res.status(404).json({ error: 'Website not found' })];
                }
                api = new wpsec_1.WPSecAPI(domain);
                // Check core integrity
                logger_1.logger.debug({
                    message: 'Running core integrity check via WPSec API',
                    domain: domain
                }, {
                    component: 'sites-controller',
                    event: 'run_core_check'
                });
                return [4 /*yield*/, api.checkCoreIntegrity()];
            case 2:
                result = _c.sent();
                logger_1.logger.info({
                    message: 'Core integrity check completed',
                    domain: domain,
                    status: result.status,
                    totalModifiedFiles: ((_a = result.modified_files) === null || _a === void 0 ? void 0 : _a.length) || 0,
                    totalMissingFiles: ((_b = result.missing_files) === null || _b === void 0 ? void 0 : _b.length) || 0
                }, {
                    component: 'sites-controller',
                    event: 'core_check_completed'
                });
                res.json(result);
                return [3 /*break*/, 4];
            case 3:
                error_3 = _c.sent();
                errorDomain = req.params.domain;
                logger_1.logger.error({
                    message: 'Error checking core integrity',
                    error: error_3,
                    domain: errorDomain
                }, {
                    component: 'sites-controller',
                    event: 'core_check_error'
                });
                res.status(500).json({ error: error_3.message });
                return [3 /*break*/, 4];
            case 4: return [2 /*return*/];
        }
    });
}); });
exports.default = router;
