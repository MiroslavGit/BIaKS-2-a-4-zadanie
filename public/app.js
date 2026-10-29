const $ = (selector) => document.querySelector(selector);
const cards = document.querySelectorAll('[data-scenario]');
const modeButtons = document.querySelectorAll('.mode-button');
const controls = document.querySelectorAll('#login-form input, #login-form textarea, #login-form button, .mode-button, .scenario-card, #reset-button');
const roles = { administrator: 'správca', student: 'študent', guest: 'hosť' };
const scenarios = {
  normal: { username: 'student', password: 'student123' },
  wrong: { username: 'student', password: 'wrong-password' },
  bypass: { username: "' OR 1=1 --", password: 'anything' },
  targeted: { username: "admin' --", password: 'wrong-password' },
  change: { username: "'; UPDATE users SET password = 'changed123' WHERE username = 'student'; --", password: 'anything' },
};
let mode = 'vulnerable';
let busy = false;

// Obe stránky používajú ten istý HTML súbor.
const isLab = location.pathname === '/sql-injection';
$('#home-page').hidden = isLab;
$('#lab-page').hidden = !isLab;
const activeNav = $(isLab ? '#nav-sql' : '#nav-home');
activeNav.classList.add('active');
activeNav.setAttribute('aria-current', 'page');
$('#breadcrumb-page').textContent = isLab ? 'SQL injekcia' : 'Prehľad';
document.title = isLab ? 'SQL injekcia · BIaKS' : 'Bezpečnostné laboratórium BIaKS';

// Reset obnoví pôvodné texty z HTML, nemusia byť napísané druhýkrát v JS.
const initialText = {};
for (const id of ['query-code', 'inspector-mode', 'input-values', 'binding-label', 'parameter-values',
  'row-count', 'execution-result', 'technical-explanation', 'result-icon', 'result-title', 'result-detail']) {
  initialText[id] = $(`#${id}`).textContent;
}
function notify(message, error = false) {
  $('#notification').textContent = message;
  $('#notification').classList.toggle('error', error);
  $('#notification').hidden = false;
}
function selectScenario(selected) {
  for (const card of cards) {
    card.classList.toggle('loaded', card === selected);
    card.setAttribute('aria-pressed', String(card === selected));
  }
}
function setBusy(value) {
  busy = value;
  for (const control of controls) control.disabled = value;
  $('#login-form').setAttribute('aria-busy', String(value));
  $('#login-button').firstChild.textContent = value ? 'Vykonávam SQL…' : 'Prihlásiť sa';
}
function showPassword(show) {
  $('#password').type = show ? 'text' : 'password';
  $('#show-password').textContent = show ? 'Skryť' : 'Zobraziť';
  $('#show-password').setAttribute('aria-pressed', String(show));
}

// SQL vkladáme ako text, nikdy ako HTML z používateľského vstupu.
function showQuery(query) {
  const tokens = query.split(/(--[^\n]*|'(?:''|[^'])*'|\b(?:SELECT|UPDATE|SET|FROM|WHERE|AND|OR|AS|UNION|ORDER|BY|LIMIT|NULL)\b|\?|\b\d+\b)/gi);
  $('#query-code').replaceChildren(...tokens.map((token) => {
    let type = '';
    if (token.startsWith('--')) type = 'comment';
    else if (token.startsWith("'")) type = 'string';
    else if (token === '?') type = 'parameter';
    else if (/^\d+$/.test(token)) type = 'number';
    else if (/^(SELECT|UPDATE|SET|FROM|WHERE|AND|OR|AS|UNION|ORDER|BY|LIMIT|NULL)$/i.test(token)) type = 'keyword';
    const span = document.createElement('span');
    if (type) span.className = `sql-${type}`;
    span.textContent = token;
    return span;
  }));
}
function showResult(data) {
  const i = data.inspector;
  const batch = data.operation === 'batch';
  const rows = batch ? i.result?.accountsAfter ?? [] : data.users;
  const summary = batch ? `Zmenené riadky: ${i.affectedRows} (UPDATE)` : `Vrátené riadky: ${i.returnedRows} (.all())`;
  const titles = {
    authenticated: 'Prihlásenie úspešné', bypassed: 'Prihlásenie obídené',
    'password-changed': 'Heslo zmenené', rejected: batch ? 'Žiadny účet sa nezmenil' : 'Prihlásenie zamietnuté', 'sql-error': 'Chyba pri vykonaní SQL'
  };
  showQuery(i.query);
  $('#copy-query').disabled = false;
  $('#inspector-mode').textContent = `${data.mode === 'secure' ? 'ZABEZPEČENÝ' : 'ZRANITEĽNÝ'} · POSLEDNÝ POKUS`;
  $('#inspector-mode').className = `badge ${data.mode === 'secure' ? 'badge-green' : 'badge-danger'}`;
  $('#input-values').textContent = JSON.stringify({ 'Používateľské meno': i.inputs.username, Heslo: i.inputs.password }, null, 2);
  $('#binding-label').textContent = data.mode === 'secure' ? 'PARAMETRE (V PORADÍ)' : 'ZOSTAVENIE DOTAZU';
  $('#parameter-values').textContent = data.mode === 'secure' ? JSON.stringify(i.parameters, null, 2) : 'Priame spájanie textov\nBez viazania parametrov';
  $('#row-count').textContent = summary;
  $('#execution-result').textContent = i.sqlError ? `CHYBA SQLITE\n${i.sqlError}` : [
    `Výsledok: ${titles[data.outcome]}`, summary, '', 'ID | meno | uložené heslo | rola',
    ...rows.map((u) => `${u.id} | ${u.username} | ${u.password} | ${roles[u.role] ?? u.role}`),
    ...(rows.length ? [] : ['(žiadne účty)']),
  ].join('\n');
  $('#technical-explanation').textContent = i.explanation;
  $('#login-result').className = `login-result ${data.outcome}`;
  $('#result-icon').textContent = data.success ? '✓' : '×';
  $('#result-title').textContent = titles[data.outcome];
  $('#result-detail').textContent = i.sqlError ? 'SQL sa nepodarilo vykonať. Podrobnosti nájdete v SQL inšpektore.' : batch ? `Počet zmenených účtov: ${i.affectedRows}. Inšpektor zobrazuje uložený stav po vykonaní SQL.` : rows.length ? rows.map((u) => `${u.username} · ${roles[u.role] ?? u.role} · uložené heslo: ${u.password}`).join('\n') : 'Žiadny účet nezodpovedá vstupom. Prístup bol zamietnutý.';
}

// Spoločné odoslanie JSON, zamknutie formulára a spracovanie chýb.
async function post(endpoint, body = {}) {
  if (busy) return null;
  setBusy(true);
  $('#notification').hidden = true;
  try {
    const response = await fetch(`/api/sql-injection/${endpoint}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body), signal: AbortSignal.timeout(15000),
    });
    const data = await response.json();
    if (!response.ok && !data.inspector) throw new Error(data.error ?? 'Požiadavka zlyhala.');
    return data;
  } catch (error) {
    const messages = {
      TimeoutError: 'Server neodpovedal včas. Skúste to znova.',
      TypeError: 'Nepodarilo sa spojiť s lokálnym serverom. Skontrolujte, či aplikácia beží.',
      SyntaxError: 'Server vrátil neplatnú odpoveď.',
    };
    notify(messages[error.name] ?? error.message, true);
    return null;
  } finally {
    setBusy(false);
  }
}
for (const button of modeButtons) button.onclick = () => {
  if (busy) return;
  mode = button.id === 'mode-secure' ? 'secure' : 'vulnerable';
  for (const item of modeButtons) {
    item.classList.toggle('selected', item === button);
    item.setAttribute('aria-pressed', String(item === button));
  }
  $('#mode-hint').classList.toggle('secure', mode === 'secure');
  $('#mode-description').textContent = mode === 'secure' ? 'Vstupy sa viažu ako parametre oddelene od SQL.' : 'Vstup sa vkladá priamo do SQL.';
};
for (const card of cards) card.onclick = () => {
  const values = scenarios[card.dataset.scenario];
  $('#username').value = values.username;
  $('#password').value = values.password;
  selectScenario(card);
  $('#notification').hidden = true;
  $('#username').focus();
};
for (const input of [$('#username'), $('#password')]) input.oninput = () => selectScenario(null);
$('#show-password').onclick = () => showPassword($('#password').type === 'password');
$('#login-form').onsubmit = async (event) => {
  event.preventDefault();
  if (!$('#username').value || !$('#password').value) {
    notify('Vyplňte používateľské meno aj heslo.', true);
    return;
  }
  const data = await post(`${mode}-login`, { username: $('#username').value, password: $('#password').value });
  if (data) showResult(data);
};
$('#reset-button').onclick = async () => {
  if (!await post('reset')) return;
  $('#login-form').reset();
  for (const [id, text] of Object.entries(initialText)) $(`#${id}`).textContent = text;
  $('#inspector-mode').className = 'badge badge-neutral';
  $('#login-result').className = 'login-result';
  $('#copy-query').disabled = true;
  showPassword(false);
  selectScenario(null);
  notify('Databáza bola obnovená. Všetky tri pôvodné účty sú opäť dostupné.');
};
$('#copy-query').onclick = async () => {
  try {
    await navigator.clipboard.writeText($('#query-code').textContent);
    notify('Vykonaný SQL príkaz bol skopírovaný do schránky.');
  } catch {
    notify('Schránka nie je dostupná. Označte text SQL a skopírujte ho ručne.', true);
  }
};
