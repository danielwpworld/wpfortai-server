"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyWebhook = verifyWebhook;
var crypto = require("crypto");
var WEBHOOK_TOLERANCE_SECONDS = 300; // 5 minutes
function verifyWebhook(websiteSecret) {
    return function (req, res, next) {
        try {
            var signature = req.header('x-wpfort-signature');
            var timestamp = req.header('x-wpfort-timestamp');
            if (!signature || !timestamp) {
                return res.status(401).json({ error: 'Missing required headers' });
            }
            // Verify timestamp is recent
            var timestampNum = parseInt(timestamp, 10);
            var now = Math.floor(Date.now() / 1000);
            if (Math.abs(now - timestampNum) > WEBHOOK_TOLERANCE_SECONDS) {
                return res.status(401).json({ error: 'Request timestamp too old' });
            }
            // Create signature
            var payload = JSON.stringify(req.body);
            var signatureData = "".concat(timestamp, ".").concat(payload);
            var expectedSignature = crypto
                .createHmac('sha256', websiteSecret)
                .update(signatureData)
                .digest('hex');
            // Compare signatures
            if (signature !== expectedSignature) {
                return res.status(401).json({ error: 'Invalid signature' });
            }
            next();
        }
        catch (error) {
            console.error('Error verifying webhook:', error);
            res.status(500).json({ error: 'Error verifying webhook' });
        }
    };
}
