import { createApp } from './app.js';
import { openDatabase } from './modules/sql-injection/database.js';

const db = openDatabase();
const app = createApp({ sqlInjectionDb: db });
const server = app.listen(3000, '127.0.0.1', () => {
  console.log('BIaKS Security Lab → http://localhost:3000');
  console.log('Listening only on 127.0.0.1. Intentionally vulnerable educational environment.');
});

server.on('error', (error) => {
  console.error(error.code === 'EADDRINUSE' ? 'Port 3000 is already in use. Stop the other server and retry.' : error);
  db.close();
  process.exitCode = 1;
});

function shutdown() {
  server.close(() => {
    if (db.open) db.close();
  });
  server.closeIdleConnections();
}
process.once('SIGINT', shutdown);
process.once('SIGTERM', shutdown);
