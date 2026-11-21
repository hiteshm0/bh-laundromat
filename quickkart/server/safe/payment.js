const { createHmac, timingSafeEqual, randomUUID } = require('node:crypto');
const { getConfig } = require('./config');

function createPaymentVerifier() {
  const receipts = new Map();
  function confirm(orderId, userId) {
    const paymentId = randomUUID();
    const signature = createHmac('sha256', getConfig().paymentSecret).update(`${orderId}|${paymentId}`).digest('hex');
    receipts.set(paymentId, { orderId, userId, signature, status: 'captured' });
    return { paymentId, signature };
  }
  function verify(orderId, userId, paymentId, signature) {
    const receipt = receipts.get(paymentId);
    if (!receipt || receipt.orderId !== orderId || receipt.userId !== userId || receipt.status !== 'captured') return false;
    if (typeof signature !== 'string' || !/^[a-f0-9]{64}$/.test(signature)) return false;
    return timingSafeEqual(Buffer.from(receipt.signature, 'hex'), Buffer.from(signature, 'hex'));
  }
  return { confirm, verify };
}

module.exports = { createPaymentVerifier };
