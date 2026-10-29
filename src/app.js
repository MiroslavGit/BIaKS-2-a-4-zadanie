import express from 'express';
import { fileURLToPath } from 'node:url';
import { sqlInjectionRouter } from './modules/sql-injection/routes.js';

const publicPath = fileURLToPath(new URL('../public/', import.meta.url));

export function createApp({ sqlInjectionDb }) {
  const app = express();
  app.disable('x-powered-by');
  app.use((req, res, next) => {
    res.set({
      'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      'Cache-Control': 'no-store',
    });
    // Local binding + Host checking prevents access via DNS rebinding.
    if (!/^(localhost|127\.0\.0\.1)(:\d+)?$/i.test(req.get('host') ?? '')) {
      return res.status(403).json({ error: 'Laboratórium prijíma iba lokálne požiadavky.' });
    }
    const origin = req.get('origin');
    if ((origin && origin !== `http://${req.get('host')}`) || req.get('sec-fetch-site') === 'cross-site') {
      return res.status(403).json({ error: 'Požiadavky z cudzej stránky nie sú povolené.' });
    }
    next();
  });
  app.use(express.json({ limit: '8kb' }));
  app.use('/api/sql-injection', sqlInjectionRouter(sqlInjectionDb));
  // Future modules receive their own router and database dependency here.
  app.use('/api', (_req, res) => res.status(404).json({ error: 'Neznámy koncový bod API.' }));
  app.get(['/', '/sql-injection'], (_req, res) => res.sendFile(`${publicPath}/index.html`));
  app.use(express.static(publicPath, { index: false, dotfiles: 'deny' }));
  app.use((_req, res) => res.status(404).type('html').send('<!doctype html><html lang="sk"><meta charset="utf-8"><title>Stránka sa nenašla</title><p>Stránka sa nenašla. <a href="/">Späť na úvodnú stránku</a>.</p></html>'));
  app.use((error, _req, res, _next) => {
    const status = error.status === 413 ? 413 : error.type === 'entity.parse.failed' ? 400 : 500;
    if (status === 500) console.error(error);
    res.status(status).json({ error: status === 413 ? 'Telo požiadavky je príliš veľké.' : status === 400 ? 'Neplatný formát JSON.' : 'Neočakávaná chyba servera.' });
  });
  return app;
}
