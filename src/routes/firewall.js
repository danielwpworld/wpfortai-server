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
// Get firewall status
router.get('/:domain/status', function (req, res) { return __awaiter(void 0, void 0, void 0, function () {
    var domain, website, api, status_1, error_1, errorDomain;
    var _a;
    return __generator(this, function (_b) {
        switch (_b.label) {
            case 0:
                _b.trys.push([0, 3, , 4]);
                domain = req.params.domain;
                logger_1.logger.debug({
                    message: 'Getting firewall status',
                    domain: domain
                }, {
                    component: 'firewall-controller',
                    event: 'get_firewall_status'
                });
                return [4 /*yield*/, (0, db_1.getWebsiteByDomain)(domain)];
            case 1:
                website = _b.sent();
                if (!website) {
                    return [2 /*return*/, res.status(404).json({ error: 'Website not found' })];
                }
                api = new wpsec_1.WPSecAPI(domain);
                // Get firewall status
                logger_1.logger.debug({
                    message: 'Fetching firewall status from WPSec API',
                    domain: domain
                }, {
                    component: 'firewall-controller',
                    event: 'fetch_firewall_status'
                });
                return [4 /*yield*/, api.getFirewallStatus()];
            case 2:
                status_1 = _b.sent();
                logger_1.logger.info({
                    message: 'Firewall status retrieved',
                    domain: domain,
                    isActive: status_1.active,
                    totalRules: ((_a = status_1.rules) === null || _a === void 0 ? void 0 : _a.length) || 0
                }, {
                    component: 'firewall-controller',
                    event: 'firewall_status_retrieved'
                });
                res.json(status_1);
                return [3 /*break*/, 4];
            case 3:
                error_1 = _b.sent();
                errorDomain = req.params.domain;
                logger_1.logger.error({
                    message: 'Error getting firewall status',
                    error: error_1,
                    domain: errorDomain
                }, {
                    component: 'firewall-controller',
                    event: 'firewall_status_error'
                });
                res.status(500).json({ error: error_1.message });
                return [3 /*break*/, 4];
            case 4: return [2 /*return*/];
        }
    });
}); });
// Toggle firewall
router.post('/:domain/toggle', function (req, res) { return __awaiter(void 0, void 0, void 0, function () {
    var domain, active, website, api, error_2;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                _a.trys.push([0, 3, , 4]);
                domain = req.params.domain;
                active = req.body.active;
                logger_1.logger.debug({
                    message: 'Toggling firewall status',
                    domain: domain,
                    targetState: active
                }, {
                    component: 'firewall-controller',
                    event: 'toggle_firewall'
                });
                if (typeof active !== 'boolean') {
                    return [2 /*return*/, res.status(400).json({ error: 'active parameter must be a boolean' })];
                }
                return [4 /*yield*/, (0, db_1.getWebsiteByDomain)(domain)];
            case 1:
                website = _a.sent();
                if (!website) {
                    return [2 /*return*/, res.status(404).json({ error: 'Website not found' })];
                }
                api = new wpsec_1.WPSecAPI(domain);
                // Toggle firewall
                logger_1.logger.debug({
                    message: 'Sending toggle request to WPSec API',
                    domain: domain,
                    targetState: active
                }, {
                    component: 'firewall-controller',
                    event: 'toggle_firewall_request'
                });
                return [4 /*yield*/, api.toggleFirewall(active)];
            case 2:
                _a.sent();
                logger_1.logger.info({
                    message: 'Firewall status toggled successfully',
                    domain: domain,
                    newState: active
                }, {
                    component: 'firewall-controller',
                    event: 'firewall_toggled'
                });
                res.json({ success: true });
                return [3 /*break*/, 4];
            case 3:
                error_2 = _a.sent();
                console.error('Error toggling firewall:', error_2);
                res.status(500).json({ error: error_2.message });
                return [3 /*break*/, 4];
            case 4: return [2 /*return*/];
        }
    });
}); });
// Get firewall logs
router.get('/:domain/logs', function (req, res) { return __awaiter(void 0, void 0, void 0, function () {
    var domain, period, website, api, logs, error_3;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                _a.trys.push([0, 3, , 4]);
                domain = req.params.domain;
                period = req.query.period;
                logger_1.logger.debug({
                    message: 'Getting firewall logs',
                    domain: domain,
                    period: period
                }, {
                    component: 'firewall-controller',
                    event: 'get_firewall_logs'
                });
                return [4 /*yield*/, (0, db_1.getWebsiteByDomain)(domain)];
            case 1:
                website = _a.sent();
                if (!website) {
                    return [2 /*return*/, res.status(404).json({ error: 'Website not found' })];
                }
                api = new wpsec_1.WPSecAPI(domain);
                // Get firewall logs
                logger_1.logger.debug({
                    message: 'Fetching firewall logs from WPSec API',
                    domain: domain,
                    period: period
                }, {
                    component: 'firewall-controller',
                    event: 'fetch_firewall_logs'
                });
                return [4 /*yield*/, api.getFirewallLogs(period ? parseInt(period) : undefined)];
            case 2:
                logs = _a.sent();
                logger_1.logger.info({
                    message: 'Firewall logs retrieved',
                    domain: domain,
                    period: period,
                    totalLogs: logs.length || 0
                }, {
                    component: 'firewall-controller',
                    event: 'firewall_logs_retrieved'
                });
                res.json(logs);
                return [3 /*break*/, 4];
            case 3:
                error_3 = _a.sent();
                console.error('Error getting firewall logs:', error_3);
                res.status(500).json({ error: error_3.message });
                return [3 /*break*/, 4];
            case 4: return [2 /*return*/];
        }
    });
}); });
// Whitelist IP
router.post('/:domain/whitelist', function (req, res) { return __awaiter(void 0, void 0, void 0, function () {
    var domain, _a, ip, action, website, api, error_4, errorDomain;
    return __generator(this, function (_b) {
        switch (_b.label) {
            case 0:
                _b.trys.push([0, 3, , 4]);
                domain = req.params.domain;
                _a = req.body, ip = _a.ip, action = _a.action;
                logger_1.logger.debug({
                    message: 'Managing firewall whitelist',
                    domain: domain,
                    ip: ip,
                    action: action
                }, {
                    component: 'firewall-controller',
                    event: 'manage_whitelist'
                });
                if (!ip || !action || !['add', 'remove'].includes(action)) {
                    return [2 /*return*/, res.status(400).json({ error: 'ip and action (add/remove) are required' })];
                }
                return [4 /*yield*/, (0, db_1.getWebsiteByDomain)(domain)];
            case 1:
                website = _b.sent();
                if (!website) {
                    return [2 /*return*/, res.status(404).json({ error: 'Website not found' })];
                }
                api = new wpsec_1.WPSecAPI(domain);
                // Whitelist IP
                logger_1.logger.debug({
                    message: 'Sending whitelist request to WPSec API',
                    domain: domain,
                    ip: ip,
                    action: action
                }, {
                    component: 'firewall-controller',
                    event: 'whitelist_request'
                });
                return [4 /*yield*/, api.whitelistFirewallIP(ip, action)];
            case 2:
                _b.sent();
                logger_1.logger.info({
                    message: "IP ".concat(action === 'add' ? 'added to' : 'removed from', " whitelist"),
                    domain: domain,
                    ip: ip,
                    action: action
                }, {
                    component: 'firewall-controller',
                    event: 'whitelist_updated'
                });
                res.json({ success: true });
                return [3 /*break*/, 4];
            case 3:
                error_4 = _b.sent();
                errorDomain = req.params.domain;
                logger_1.logger.error({
                    message: 'Error managing firewall whitelist',
                    error: error_4,
                    domain: errorDomain,
                    ip: req.body.ip,
                    action: req.body.action
                }, {
                    component: 'firewall-controller',
                    event: 'whitelist_error'
                });
                res.status(500).json({ error: error_4.message });
                return [3 /*break*/, 4];
            case 4: return [2 /*return*/];
        }
    });
}); });
exports.default = router;
