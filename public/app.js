const $ = (selector) => document.querySelector(selector);
const isLab = window.location.pathname === '/sql-injection';
$('#home-page').hidden = isLab;
$('#lab-page').hidden = !isLab;
$(isLab ? '#nav-sql' : '#nav-home').classList.add('active');
$(isLab ? '#nav-sql' : '#nav-home').setAttribute('aria-current', 'page');
$('#breadcrumb-page').textContent = isLab ? 'SQL Injection Lab' : 'Overview';
document.title = isLab ? 'SQL Injection Lab · BIaKS' : 'BIaKS Security Lab';

const scenarios = {
  normal: { username: 'student', password: 'student123' },
  wrong: { username: 'student', password: 'wrong-password' },
  bypass: { username: "' OR 1=1 --", password: 'anything' },
  targeted: { username: "admin' --", password: 'wrong-password' },
  change: { username: "'; UPDATE users SET password = 'changed123' WHERE username = 'student'; --", password: 'anything' },
};
let mode = 'vulnerable';
let lastQuery = '';
let busy = false;

function selectScenario(selected) {
  for (const button of document.querySelectorAll('[data-scenario]')) {
    const active = button === selected;
    button.classList.toggle('loaded', active);
    button.setAttribute('aria-pressed', String(active));
  }
}

function notify(message, error = false) {
  $('#notification').hidden = false;
  $('#notification').classList.toggle('error', error);
  $('#notification').textContent = message;
}

function setBusy(value) {
  busy = value;
  for (const element of document.querySelectorAll('#login-form input, #login-form textarea, #login-form button, .mode-button, .scenario-card, #reset-button')) {
    element.disabled = value;
  }
  $('#login-form').setAttribute('aria-busy', String(value));
  $('#login-button').firstChild.textContent = value ? 'Executing query…' : 'Login';
}

function selectMode(value) {
  if (busy) return;
  mode = value;
  for (const name of ['vulnerable', 'secure']) {
    const button = $(`#mode-${name}`);
    button.classList.toggle('selected', name === mode);
    button.classList.toggle('secure', name === 'secure' && name === mode);
    button.setAttribute('aria-pressed', String(name === mode));
  }
  $('#mode-hint').classList.toggle('secure', mode === 'secure');
  $('#mode-description').textContent = mode === 'secure' ? 'Values are bound as parameters, separate from SQL.' : 'Input is concatenated directly into the login SQL.';
}

// Build highlighted tokens with text nodes only. SQL input is never HTML.
function highlightSql(query) {
  const code = document.createElement('code');
  const tokens = query.split(/(--[^\n]*|'(?:''|[^'])*'|\b(?:SELECT|UPDATE|SET|FROM|WHERE|AND|OR|AS|UNION|ORDER|BY|LIMIT|NULL)\b|\?|\b\d+\b)/gi);
  for (const token of tokens) {
    let type;
    if (token.startsWith('--')) type = 'comment';
    else if (token.startsWith("'")) type = 'string';
    else if (token === '?') type = 'parameter';
    else if (/^\d+$/.test(token)) type = 'number';
    else if (/^(SELECT|UPDATE|SET|FROM|WHERE|AND|OR|AS|UNION|ORDER|BY|LIMIT|NULL)$/i.test(token)) type = 'keyword';
    if (!type) code.append(document.createTextNode(token));
    else {
      const span = document.createElement('span');
      span.className = `sql-${type}`;
      span.textContent = token;
      code.append(span);
    }
  }
  $('#query-code').replaceChildren(code);
}

function showResult(data) {
  const { inspector } = data;
  lastQuery = inspector.query;
  highlightSql(lastQuery);
  $('#copy-query').disabled = false;
  const badge = $('#inspector-mode');
  badge.textContent = `${data.mode.toUpperCase()} · LAST REQUEST`;
  badge.className = `badge ${data.mode === 'secure' ? 'badge-green' : 'badge-danger'}`;
  $('#input-values').textContent = JSON.stringify(inspector.inputs, null, 2);
  $('#binding-label').textContent = data.mode === 'secure' ? 'BOUND PARAMETERS (IN ORDER)' : 'QUERY CONSTRUCTION';
  $('#parameter-values').textContent = data.mode === 'secure' ? JSON.stringify(inspector.parameters, null, 2) : 'Direct string concatenation\nNo parameter binding';
  const changing = data.operation === 'batch';
  $('#row-count').textContent = changing ? `${inspector.affectedRows} ${inspector.affectedRows === 1 ? 'row' : 'rows'} affected by UPDATE` : `${inspector.returnedRows} ${inspector.returnedRows === 1 ? 'row' : 'rows'} returned by .all()`;
  const accounts = changing ? inspector.result?.accountsAfter ?? [] : inspector.result;
  $('#execution-result').textContent = inspector.sqlError ? `SQLITE ERROR\n${inspector.sqlError}` : [
    '{',
    `  "outcome": ${JSON.stringify(data.outcome)},`,
    ...(changing ? [`  "affectedRows": ${inspector.affectedRows},`] : []),
    `  "${changing ? 'accountsAfter' : 'accounts'}": [`,
    accounts.map((account) => `    ${JSON.stringify(account)}`).join(',\n'),
    '  ]',
    '}',
  ].join('\n');
  $('#technical-explanation').textContent = inspector.explanation;

  const titles = { authenticated: 'Login successful', bypassed: 'Authentication bypassed', 'password-changed': 'Password changed', rejected: changing ? 'Password change rejected' : 'Login rejected', 'sql-error': 'SQL execution error' };
  const container = $('#login-result');
  container.className = `login-result ${data.outcome}`;
  const mark = document.createElement('span');
  mark.className = 'result-idle-mark';
  mark.textContent = data.success ? '✓' : '×';
  const text = document.createElement('div');
  const title = document.createElement('strong');
  title.textContent = titles[data.outcome];
  const detail = document.createElement('p');
  if (inspector.sqlError) {
    detail.textContent = 'Invalid SQL. Review the Query Inspector.';
  } else if (changing) {
    detail.textContent = data.success ? `The SQL entered in Username updated ${inspector.affectedRows} account(s). The inspector shows the stored state after execution.` : 'No account updated. The stored passwords are unchanged.';
  } else {
    detail.textContent = data.users.length > 0 ? data.users.map((user) => `${user.username} · ${user.role} · stored password: ${user.password}`).join('\n') : 'No matching synthetic account. Access denied.';
  }
  text.append(title, detail);
  container.replaceChildren(mark, text);
}

async function post(endpoint, body = {}) {
  const response = await fetch(`/api/sql-injection/${endpoint}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(15000),
  });
  const data = await response.json();
  if (!response.ok && !data.inspector) throw new Error(data.error ?? 'The request failed.');
  return data;
}

$('#mode-vulnerable').addEventListener('click', () => selectMode('vulnerable'));
$('#mode-secure').addEventListener('click', () => selectMode('secure'));
for (const button of document.querySelectorAll('[data-scenario]')) {
  button.addEventListener('click', () => {
    const values = scenarios[button.dataset.scenario];
    $('#username').value = values.username;
    $('#password').value = values.password;
    selectScenario(button);
    $('#notification').hidden = true;
    $('#username').focus();
  });
}
for (const input of document.querySelectorAll('#login-form input, #login-form textarea')) {
  input.addEventListener('input', () => {
    selectScenario(null);
  });
}
$('#show-password').addEventListener('click', () => {
  const show = $('#password').type === 'password';
  $('#password').type = show ? 'text' : 'password';
  $('#show-password').textContent = show ? 'Hide' : 'Show';
  $('#show-password').setAttribute('aria-pressed', String(show));
});
$('#login-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  if (busy) return;
  const inputs = { username: $('#username').value, password: $('#password').value };
  setBusy(true);
  $('#notification').hidden = true;
  try {
    showResult(await post(`${mode}-login`, inputs));
  } catch (error) {
    notify(`Request failed: ${error.message} Check that the local server is running and try again.`, true);
  } finally {
    setBusy(false);
  }
});
$('#reset-button').addEventListener('click', async () => {
  if (busy) return;
  setBusy(true);
  try {
    await post('reset');
    $('#login-form').reset();
    $('#password').type = 'password';
    $('#show-password').textContent = 'Show';
    $('#show-password').setAttribute('aria-pressed', 'false');
    lastQuery = '';
    $('#copy-query').disabled = true;
    highlightSql('-- Database reset. Submit a login to execute a new query.');
    $('#inspector-mode').textContent = 'AWAITING QUERY';
    $('#inspector-mode').className = 'badge badge-neutral';
    $('#input-values').textContent = 'No request yet.';
    $('#binding-label').textContent = 'QUERY CONSTRUCTION';
    $('#parameter-values').textContent = 'Waiting for execution.';
    $('#row-count').textContent = '— rows returned';
    $('#execution-result').textContent = 'No query has been executed.';
    $('#technical-explanation').textContent = 'Databáza bola obnovená na tri pôvodné syntetické účty. Vyberte príklad a kliknite na Login.';
    $('#login-result').className = 'login-result';
    const title = document.createElement('strong');
    title.textContent = 'Ready to experiment';
    $('#login-result').replaceChildren(title);
    selectScenario(null);
    notify('Database reset. All three synthetic accounts have been restored.');
  } catch (error) {
    notify(`Reset failed: ${error.message}`, true);
  } finally {
    setBusy(false);
  }
});
$('#copy-query').addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText(lastQuery);
    notify('Executed SQL copied to clipboard.');
  } catch {
    notify('Clipboard is unavailable. Select the query text and copy it manually.', true);
  }
});
