// server.js
const app = require('./app');
const { connectDB } = require('./config/db');

const PORT = process.env.PORT || 4000;

async function start() {
  await connectDB();
  app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
}

// start only when executed directly (not when imported by /api/index.js)
if (require.main === module) {
  start().catch(err => {
    console.error('Failed to start', err);
    process.exit(1);
  });
}
