require('dotenv').config({ path: require('node:path').join(__dirname, '.env') });
const { createDatabase } = require('./db');
const { createApp } = require('./app');
const config = require('./config');

if (!config.jwtSecret) throw new Error('JWT_SECRET is required');
const db = createDatabase();
const server = createApp(db).listen(config.port, '127.0.0.1', () => {
  console.log(`QuickKart running at http://127.0.0.1:${config.port}`);
});
process.on('SIGINT', () => server.close(() => { db.close(); process.exit(0); }));
process.on('SIGTERM', () => server.close(() => { db.close(); process.exit(0); }));
