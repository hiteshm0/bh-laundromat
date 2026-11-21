function getConfig() {
  return {
    razorpayKeyId: process.env.SAFE_RAZORPAY_KEY_ID,
    razorpayKeySecret: process.env.SAFE_RAZORPAY_KEY_SECRET,
    stripeKey: process.env.STRIPE_SECRET_KEY,
    jwtSecret: process.env.JWT_SECRET,
    paymentSecret: process.env.SAFE_PAYMENT_SECRET
  };
}

module.exports = { getConfig };
