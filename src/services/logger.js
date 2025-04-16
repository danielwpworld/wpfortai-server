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
exports.logger = void 0;
var cloki_1 = require("@miketako3/cloki");
var Logger = /** @class */ (function () {
    function Logger() {
        // Get log level from env or default to info
        var logLevel = (process.env.LOG_LEVEL || 'info').toLowerCase();
        this.cloki = (0, cloki_1.getLokiLogger)({
            lokiHost: process.env.GRAFANA_LOKI_HOST,
            lokiUser: process.env.GRAFANA_LOKI_USER,
            lokiToken: process.env.GRAFANA_LOKI_TOKEN
        });
        this.defaultLabels = {
            app: 'wpfort',
            environment: process.env.NODE_ENV || 'development',
            service: 'api'
        };
    }
    Logger.prototype.info = function (data_1) {
        return __awaiter(this, arguments, void 0, function (data, labels) {
            if (labels === void 0) { labels = {}; }
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.cloki.info(__assign({}, data), __assign(__assign({}, this.defaultLabels), labels))];
                    case 1:
                        _a.sent();
                        return [2 /*return*/];
                }
            });
        });
    };
    Logger.prototype.error = function (data_1) {
        return __awaiter(this, arguments, void 0, function (data, labels) {
            var errorData;
            var _a, _b, _c;
            if (labels === void 0) { labels = {}; }
            return __generator(this, function (_d) {
                switch (_d.label) {
                    case 0:
                        errorData = __assign(__assign({}, data), { stack: (_a = data.error) === null || _a === void 0 ? void 0 : _a.stack, errorName: (_b = data.error) === null || _b === void 0 ? void 0 : _b.name, errorMessage: (_c = data.error) === null || _c === void 0 ? void 0 : _c.message });
                        return [4 /*yield*/, this.cloki.error(errorData, __assign(__assign({}, this.defaultLabels), labels))];
                    case 1:
                        _d.sent();
                        return [2 /*return*/];
                }
            });
        });
    };
    Logger.prototype.warn = function (data_1) {
        return __awaiter(this, arguments, void 0, function (data, labels) {
            if (labels === void 0) { labels = {}; }
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.cloki.warn(__assign({}, data), __assign(__assign({}, this.defaultLabels), labels))];
                    case 1:
                        _a.sent();
                        return [2 /*return*/];
                }
            });
        });
    };
    Logger.prototype.debug = function (data_1) {
        return __awaiter(this, arguments, void 0, function (data, labels) {
            var logLevel;
            if (labels === void 0) { labels = {}; }
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        logLevel = (process.env.LOG_LEVEL || 'info').toLowerCase();
                        if (!(logLevel === 'debug')) return [3 /*break*/, 2];
                        return [4 /*yield*/, this.cloki.debug(__assign({}, data), __assign(__assign({}, this.defaultLabels), labels))];
                    case 1:
                        _a.sent();
                        _a.label = 2;
                    case 2: return [2 /*return*/];
                }
            });
        });
    };
    return Logger;
}());
exports.logger = new Logger();
