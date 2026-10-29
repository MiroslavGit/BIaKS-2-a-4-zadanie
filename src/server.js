import { createApp } from './app.js';
import { openDatabase } from './modules/sql-injection/database.js';

const db = openDatabase();
const app = createApp({ sqlInjectionDb: db });
const server = app.listen(3000, '127.0.0.1', () => {
  console.log('Bezpečnostné laboratórium BIaKS → http://localhost:3000');
  console.log('Server počúva iba na 127.0.0.1. Zámerne zraniteľné školské prostredie.');
});

server.on('error', (error) => {
  console.error(error.code === 'EADDRINUSE' ? 'Port 3000 je obsadený. Ukončite druhý server a skúste to znova.' : error);
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
