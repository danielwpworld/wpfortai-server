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
exports.ScanStore = void 0;
var redis_1 = require("../config/redis");
var ScanStore = /** @class */ (function () {
    function ScanStore() {
    }
    ScanStore.createScan = function (domain, scanData) {
        return __awaiter(this, void 0, void 0, function () {
            var storedData, multi;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        storedData = {
                            domain: domain,
                            scan_id: scanData.scan_id,
                            started_at: scanData.started_at,
                            status: 'pending'
                        };
                        multi = redis_1.default.multi();
                        // Store scan data with TTL
                        multi.setex("".concat(this.SCAN_KEY_PREFIX).concat(scanData.scan_id), this.SCAN_TTL, JSON.stringify(storedData));
                        // Set this scan as the active scan for the domain
                        multi.set("".concat(this.ACTIVE_SCAN_KEY_PREFIX).concat(domain), scanData.scan_id);
                        return [4 /*yield*/, multi.exec()];
                    case 1:
                        _a.sent();
                        return [2 /*return*/];
                }
            });
        });
    };
    ScanStore.updateScanStatus = function (scanId, status) {
        return __awaiter(this, void 0, void 0, function () {
            var key, existingData, storedData, updatedData;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        key = "".concat(this.SCAN_KEY_PREFIX).concat(scanId);
                        return [4 /*yield*/, redis_1.default.get(key)];
                    case 1:
                        existingData = _a.sent();
                        if (!existingData) {
                            throw new Error("Scan ".concat(scanId, " not found in store"));
                        }
                        storedData = JSON.parse(existingData);
                        updatedData = __assign(__assign({}, storedData), { status: status.status, progress: status.progress, files_scanned: status.files_scanned, total_files: status.total_files, completed_at: status.completed_at, duration: status.duration, results_endpoint: status.results_endpoint });
                        return [4 /*yield*/, redis_1.default.setex(key, this.SCAN_TTL, JSON.stringify(updatedData))];
                    case 2:
                        _a.sent();
                        if (!(status.status === 'completed' || status.status === 'failed')) return [3 /*break*/, 4];
                        return [4 /*yield*/, redis_1.default.del("".concat(this.ACTIVE_SCAN_KEY_PREFIX).concat(storedData.domain))];
                    case 3:
                        _a.sent();
                        _a.label = 4;
                    case 4: return [2 /*return*/];
                }
            });
        });
    };
    ScanStore.getScan = function (scanId) {
        return __awaiter(this, void 0, void 0, function () {
            var data;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, redis_1.default.get("".concat(this.SCAN_KEY_PREFIX).concat(scanId))];
                    case 1:
                        data = _a.sent();
                        return [2 /*return*/, data ? JSON.parse(data) : null];
                }
            });
        });
    };
    ScanStore.getActiveScan = function (domain) {
        return __awaiter(this, void 0, void 0, function () {
            var scanId;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, redis_1.default.get("".concat(this.ACTIVE_SCAN_KEY_PREFIX).concat(domain))];
                    case 1:
                        scanId = _a.sent();
                        if (!scanId)
                            return [2 /*return*/, null];
                        return [2 /*return*/, this.getScan(scanId)];
                }
            });
        });
    };
    ScanStore.SCAN_KEY_PREFIX = 'scan:';
    ScanStore.ACTIVE_SCAN_KEY_PREFIX = 'active_scan:';
    ScanStore.SCAN_TTL = 60 * 60 * 24; // 24 hours in seconds
    return ScanStore;
}());
exports.ScanStore = ScanStore;
