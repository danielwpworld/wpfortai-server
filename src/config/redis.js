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
var _a, _b;
Object.defineProperty(exports, "__esModule", { value: true });
exports.setActiveScan = exports.getActiveScan = void 0;
var ioredis_1 = require("ioredis");
var logger_1 = require("../services/logger");
var redis = new ioredis_1.default({
    host: (_a = process.env.REDIS_SERVER) === null || _a === void 0 ? void 0 : _a.split(':')[0],
    port: parseInt(((_b = process.env.REDIS_SERVER) === null || _b === void 0 ? void 0 : _b.split(':')[1]) || '6379'),
    username: process.env.REDIS_USERNAME,
    password: process.env.REDIS_PASSWORD
});
// Log Redis connection events
redis.on('connect', function () {
    logger_1.logger.info({
        message: 'Redis connection established'
    }, {
        component: 'redis',
        event: 'connection_established'
    });
});
redis.on('error', function (err) {
    logger_1.logger.error({
        message: 'Redis connection error',
        error: err
    }, {
        component: 'redis',
        event: 'connection_error'
    });
});
redis.on('close', function () {
    logger_1.logger.warn({
        message: 'Redis connection closed'
    }, {
        component: 'redis',
        event: 'connection_closed'
    });
});
// Helper functions for managing active scans
var getActiveScan = function (domain) { return __awaiter(void 0, void 0, void 0, function () {
    var data, scan, error_1;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                logger_1.logger.debug({
                    message: 'Getting active scan data',
                    domain: domain
                }, {
                    component: 'redis',
                    event: 'get_active_scan'
                });
                _a.label = 1;
            case 1:
                _a.trys.push([1, 3, , 4]);
                return [4 /*yield*/, redis.get("active_scan:".concat(domain))];
            case 2:
                data = _a.sent();
                scan = data ? JSON.parse(data) : null;
                logger_1.logger.debug({
                    message: scan ? 'Active scan found' : 'No active scan found',
                    domain: domain,
                    found: !!scan
                }, {
                    component: 'redis',
                    event: 'active_scan_result'
                });
                return [2 /*return*/, scan];
            case 3:
                error_1 = _a.sent();
                logger_1.logger.error({
                    message: 'Error getting active scan',
                    error: error_1,
                    domain: domain
                }, {
                    component: 'redis',
                    event: 'get_scan_error'
                });
                throw error_1;
            case 4: return [2 /*return*/];
        }
    });
}); };
exports.getActiveScan = getActiveScan;
var setActiveScan = function (domain, data) { return __awaiter(void 0, void 0, void 0, function () {
    var error_2;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                logger_1.logger.debug({
                    message: 'Setting active scan data',
                    domain: domain,
                    scanId: data.scan_id
                }, {
                    component: 'redis',
                    event: 'set_active_scan'
                });
                _a.label = 1;
            case 1:
                _a.trys.push([1, 3, , 4]);
                return [4 /*yield*/, redis.set("active_scan:".concat(domain), JSON.stringify(data))];
            case 2:
                _a.sent();
                logger_1.logger.debug({
                    message: 'Active scan data set successfully',
                    domain: domain,
                    scanId: data.scan_id
                }, {
                    component: 'redis',
                    event: 'scan_data_set'
                });
                return [3 /*break*/, 4];
            case 3:
                error_2 = _a.sent();
                logger_1.logger.error({
                    message: 'Error setting active scan',
                    error: error_2,
                    domain: domain
                }, {
                    component: 'redis',
                    event: 'set_scan_error'
                });
                throw error_2;
            case 4: return [2 /*return*/];
        }
    });
}); };
exports.setActiveScan = setActiveScan;
exports.default = redis;
