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
exports.WPSecAPI = void 0;
var node_fetch_1 = require("node-fetch");
var scan_store_1 = require("./scan-store");
var WPSecAPI = /** @class */ (function () {
    function WPSecAPI(domain) {
        this.apiKey = process.env.WPFORT_API_KEY || '';
        if (!this.apiKey) {
            throw new Error('WPFORT_API_KEY is not set in environment variables');
        }
        this.domain = domain;
    }
    WPSecAPI.prototype.request = function (endpoint_1) {
        return __awaiter(this, arguments, void 0, function (endpoint, options) {
            var requestOptions, baseUrl, url, response;
            if (options === void 0) { options = {}; }
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        requestOptions = __assign(__assign({}, options), { headers: __assign({ 'Content-Type': 'application/json', 'x-api-key': this.apiKey }, options.headers) });
                        if (options.body) {
                            requestOptions.body = JSON.stringify(options.body);
                        }
                        baseUrl = this.domain.startsWith('http') ? this.domain : "https://".concat(this.domain);
                        url = new URL(baseUrl);
                        url.searchParams.append('wpsec_endpoint', endpoint);
                        return [4 /*yield*/, (0, node_fetch_1.default)(url.toString(), requestOptions)];
                    case 1:
                        response = _a.sent();
                        if (!response.ok) {
                            throw new Error("WPSec API error: ".concat(response.statusText));
                        }
                        return [2 /*return*/, response.json()];
                }
            });
        });
    };
    // Site Information
    WPSecAPI.prototype.getSiteInfo = function () {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                return [2 /*return*/, this.request('site-info')];
            });
        });
    };
    // Vulnerabilities
    WPSecAPI.prototype.getVulnerabilities = function () {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                return [2 /*return*/, this.request('vulnerabilities')];
            });
        });
    };
    // Scanning
    WPSecAPI.prototype.startScan = function () {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.request('scan', {
                            method: 'POST'
                        })];
                    case 1:
                        response = _a.sent();
                        // Store scan data in Redis
                        return [4 /*yield*/, scan_store_1.ScanStore.createScan(this.domain, response)];
                    case 2:
                        // Store scan data in Redis
                        _a.sent();
                        return [2 /*return*/, response];
                }
            });
        });
    };
    WPSecAPI.prototype.getScanStatus = function (scanId) {
        return __awaiter(this, void 0, void 0, function () {
            var status;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.request("scan/".concat(scanId, "/status"))];
                    case 1:
                        status = _a.sent();
                        // Update scan status in Redis
                        return [4 /*yield*/, scan_store_1.ScanStore.updateScanStatus(scanId, status)];
                    case 2:
                        // Update scan status in Redis
                        _a.sent();
                        return [2 /*return*/, status];
                }
            });
        });
    };
    WPSecAPI.prototype.getScanResults = function (scanId) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                return [2 /*return*/, this.request("scan/".concat(scanId, "/results"))];
            });
        });
    };
    // Firewall Management
    WPSecAPI.prototype.toggleFirewall = function (active) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                return [2 /*return*/, this.request('firewall/toggle', {
                        method: 'POST',
                        body: { active: active }
                    })];
            });
        });
    };
    WPSecAPI.prototype.getFirewallStatus = function () {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                return [2 /*return*/, this.request('firewall/status')];
            });
        });
    };
    WPSecAPI.prototype.getFirewallLogs = function (period) {
        return __awaiter(this, void 0, void 0, function () {
            var endpoint;
            return __generator(this, function (_a) {
                endpoint = period ? "firewall/logs?period=".concat(period) : 'firewall/logs';
                return [2 /*return*/, this.request(endpoint)];
            });
        });
    };
    WPSecAPI.prototype.whitelistFirewallIP = function (ip, action) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                return [2 /*return*/, this.request('firewall/whitelist', {
                        method: 'POST',
                        body: { ip: ip, action: action }
                    })];
            });
        });
    };
    // Backup Management
    WPSecAPI.prototype.startBackup = function (type, incremental) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                return [2 /*return*/, this.request('backup/start', {
                        method: 'POST',
                        body: { type: type, incremental: incremental }
                    })];
            });
        });
    };
    WPSecAPI.prototype.getBackupStatus = function (backupId) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                return [2 /*return*/, this.request("backup/status/".concat(backupId))];
            });
        });
    };
    WPSecAPI.prototype.listBackups = function () {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                return [2 /*return*/, this.request('backup/list')];
            });
        });
    };
    WPSecAPI.prototype.restoreBackup = function (backupId) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                return [2 /*return*/, this.request("backup/restore/".concat(backupId), {
                        method: 'POST'
                    })];
            });
        });
    };
    WPSecAPI.prototype.getRestoreStatus = function (restoreId) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                return [2 /*return*/, this.request("backup/restore/".concat(restoreId, "/status"))];
            });
        });
    };
    // WordPress Core Management
    WPSecAPI.prototype.checkCoreIntegrity = function () {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                return [2 /*return*/, this.request('core-check')];
            });
        });
    };
    WPSecAPI.prototype.updateAll = function () {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                return [2 /*return*/, this.request('update-all', {
                        method: 'POST'
                    })];
            });
        });
    };
    WPSecAPI.prototype.updateItems = function (type, items) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                return [2 /*return*/, this.request('update-items', {
                        method: 'POST',
                        body: { type: type, items: items }
                    })];
            });
        });
    };
    // File Management
    WPSecAPI.prototype.whitelistFile = function (filePath, reason, addedBy) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                return [2 /*return*/, this.request('whitelist', {
                        method: 'POST',
                        body: {
                            file_path: filePath,
                            reason: reason,
                            added_by: addedBy
                        }
                    })];
            });
        });
    };
    WPSecAPI.prototype.getWhitelistedFiles = function (includeDetails, verifyIntegrity) {
        return __awaiter(this, void 0, void 0, function () {
            var endpoint;
            return __generator(this, function (_a) {
                endpoint = 'whitelist/list';
                if (includeDetails)
                    endpoint += '?include_details=1';
                if (verifyIntegrity)
                    endpoint += "".concat(includeDetails ? '&' : '?', "verify_integrity=1");
                return [2 /*return*/, this.request(endpoint)];
            });
        });
    };
    WPSecAPI.prototype.removeWhitelistedFile = function (filePath) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                return [2 /*return*/, this.request('whitelist/remove', {
                        method: 'POST',
                        body: { file_path: filePath }
                    })];
            });
        });
    };
    WPSecAPI.prototype.verifyWhitelistIntegrity = function () {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                return [2 /*return*/, this.request('whitelist/verify')];
            });
        });
    };
    WPSecAPI.prototype.cleanupWhitelist = function () {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                return [2 /*return*/, this.request('whitelist/cleanup', {
                        method: 'POST'
                    })];
            });
        });
    };
    // Quarantine Management
    WPSecAPI.prototype.quarantineFile = function (filePath) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                return [2 /*return*/, this.request('quarantine', {
                        method: 'POST',
                        body: { file_path: filePath }
                    })];
            });
        });
    };
    WPSecAPI.prototype.getQuarantinedFiles = function () {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                return [2 /*return*/, this.request('quarantine-list')];
            });
        });
    };
    WPSecAPI.prototype.restoreQuarantinedFile = function (quarantineId) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                return [2 /*return*/, this.request('quarantine/restore', {
                        method: 'POST',
                        body: { quarantine_id: quarantineId }
                    })];
            });
        });
    };
    WPSecAPI.prototype.batchFileOperation = function (operation, files) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                return [2 /*return*/, this.request('quarantine/batch', {
                        method: 'POST',
                        body: { operation: operation, files: files }
                    })];
            });
        });
    };
    return WPSecAPI;
}());
exports.WPSecAPI = WPSecAPI;
