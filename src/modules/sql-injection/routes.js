import { Router } from 'express';
import { resetDatabase } from './database.js';
import { secureLogin, vulnerableLogin } from './login.js';

function credentials(req, res, next) {
  const { username, password } = req.body ?? {};
  if (typeof username !== 'string' || typeof password !== 'string' || username.length === 0 || password.length === 0 || username.length > 500 || password.length > 500) {
    return res.status(400).json({ error: 'Username and password must be non-empty strings of at most 500 characters.' });
  }
  // Do not trim or escape: the original values matter for the demonstration.
  req.credentials = { username, password };
  next();
}

export function sqlInjectionRouter(db) {
  const router = Router();
  const respond = (res, data) => res.status(data.inspector.sqlError ? 400 : data.success ? 200 : 401).json(data);
  router.post('/vulnerable-login', credentials, (req, res) => {
    respond(res, vulnerableLogin(db, req.credentials));
  });
  router.post('/secure-login', credentials, (req, res) => {
    respond(res, secureLogin(db, req.credentials));
  });
  router.post('/reset', (_req, res) => {
    resetDatabase(db);
    res.json({ success: true, message: 'Synthetic database restored.', users: 3 });
  });
  return router;
}
