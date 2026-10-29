export const SECURE_QUERY = 'SELECT id, username, password, role FROM users WHERE username = ? AND password = ?';

// Permit only a SELECT followed by one password UPDATE in this local demo.
// This validates scope; the actual SQL and its values still come from the input.
const SQL_LITERAL = "'(?:''|[^'])*'";
const PASSWORD_BATCH = new RegExp(
  "^SELECT id, username, password, role FROM users WHERE username = '';\\s*" +
  `UPDATE\\s+users\\s+SET\\s+password\\s*=\\s*${SQL_LITERAL}` +
  `\\s+WHERE\\s+username\\s*=\\s*${SQL_LITERAL}\\s*;\\s*--[^\\r\\n]*$`, 'i',
);

// These descriptions explain the prepared inputs only. They never grant access.
const ATTACK_EXPLANATIONS = [
  {
    username: "' OR 1=1 --",
    password: 'anything',
    vulnerable: 'Apostrof ukončil používateľské meno. OR 1=1 pridal vždy pravdivú podmienku a -- zakomentovalo kontrolu hesla. SQLite preto vrátil všetky účty a .all() ich načítalo všetky. Výsledok obsahuje aj heslá skutočne uložené v databáze; anything je iba vstup, ktorý sa nekontroloval.',
    secure: 'Celý vstup \' OR 1=1 -- je naviazaný ako hodnota mena. OR nemení podmienku a -- nevytvára komentár. Parametrizovaný dotaz hľadá presne toto meno a zadané heslo; taký účet neexistuje, preto prihlásenie odmietol.',
  },
  {
    username: "admin' --",
    password: 'wrong-password',
    vulnerable: 'Apostrof za admin ukončil meno a -- zakomentovalo kontrolu hesla. Zostalo iba username = \'admin\', preto SQLite vrátil tento účet aj jeho skutočné uložené heslo. wrong-password je zadaný vstup, nie heslo účtu v databáze. Tento SELECT heslo nemení.',
    secure: 'Hodnota admin\' -- sa porovnáva ako celé používateľské meno. Apostrof ani -- nemenia SQL štruktúru a kontrola hesla zostáva aktívna. Taká dvojica mena a hesla neexistuje, preto prihlásenie neprešlo.',
  },
  {
    username: "'; UPDATE users SET password = 'changed123' WHERE username = 'student'; --",
    password: 'anything',
    secure: 'Celý vstup vrátane bodkočiarok a UPDATE je jediná hodnota parametra mena. Stále sa vykoná iba pripravený SELECT. Žiadny účet nemá toto meno; prihlasovanie sa odmietlo a heslo sa nezmenilo.',
  },
];

function explanation(mode, outcome, inputs) {
  if (outcome === 'sql-error') {
    return 'SQLite odmietol príkaz alebo jeho syntax. Laboratórium prijíma čítací SELECT alebo obmedzenú ukážku SELECT + UPDATE users SET password s výberom jedného mena. Iné dávky SQL nie sú povolené. Skontrolujte presný SQL v inšpektore.';
  }
  const attack = ATTACK_EXPLANATIONS.find(({ username, password }) =>
    username === inputs.username && password === inputs.password);
  if (mode === 'secure') {
    return outcome === 'authenticated' ? 'SQLite porovnal samostatne viazané parametre s uloženými údajmi. Prihlasovacie údaje sú správne.' : attack?.secure ?? 'SQLite spracoval meno a heslo ako samostatne viazané hodnoty. Obsah parametrov sa nevyhodnocuje ako SQL kód a nemôže zmeniť štruktúru dotazu. Žiadny účet nezodpovedá zadanému menu a heslu.';
  }
  if (outcome === 'bypassed') {
    return attack?.vulnerable ?? 'SQLite vrátil riadok, hoci zadané meno a heslo nie sú platné. V tomto režime sa vstup stal súčasťou SQL príkazu a mohol zmeniť jeho podmienku alebo výsledok. Aplikácia prijala skutočný výsledok dotazu. Presný účinok vlastného vstupu posúďte podľa zobrazeného SQL; v zabezpečenom režime zostane vstup iba hodnotou parametra.';
  }
  return outcome === 'authenticated' ? 'SQL dotaz vrátil používateľa a zadané prihlasovacie údaje sa zhodujú s databázou. Bežné prihlásenie uspelo.' : 'SQL dotaz nevrátil žiadneho používateľa. Podmienka WHERE nebola splnená a prihlásenie bolo zamietnuté.';
}

function result(db, mode, query, inputs, users, sqlError = null) {
  // This check labels the actual database result. It never grants access itself.
  const credentialsMatch = Boolean(db.prepare(SECURE_QUERY).get(inputs.username, inputs.password));
  const success = users.length > 0;
  const bypassed = success && !credentialsMatch;
  const outcome = sqlError ? 'sql-error' : !success ? 'rejected' : bypassed ? 'bypassed' : 'authenticated';
  return {
    mode,
    operation: 'login',
    success,
    bypassed,
    outcome,
    users,
    inspector: {
      query,
      inputs,
      parameters: mode === 'secure' ? [inputs.username, inputs.password] : null,
      returnedRows: users.length,
      result: users,
      sqlError,
      explanation: explanation(mode, outcome, inputs),
    },
  };
}

function executePasswordBatch(db, query, inputs) {
  return db.transaction(() => {
    // Execute the full displayed SQL verbatim. No UPDATE is constructed here.
    db.exec(query);
    const { affectedRows } = db.prepare('SELECT changes() AS affectedRows').get();
    const accountsAfter = affectedRows > 0 ? db.prepare('SELECT id, username, password, role FROM users ORDER BY id').all() : [];
    return {
      mode: 'vulnerable', operation: 'batch', success: affectedRows > 0,
      bypassed: affectedRows > 0, outcome: affectedRows > 0 ? 'password-changed' : 'rejected',
      inspector: {
        query, inputs, parameters: null, affectedRows,
        result: { affectedRows, accountsAfter }, sqlError: null,
        explanation: affectedRows > 0 ? 'Apostrof ukončil meno a prvá bodkočiarka ukončila pôvodný SELECT. Nasledujúci UPDATE je celý napísaný v poli Používateľské meno a SQLite ho vykonal ako druhý príkaz. -- zakomentovalo zvyšok pôvodného prihlasovania. Počet dotknutých riadkov aj účty po zápise pochádzajú z databázy; cieľ aj nové heslo určuje zadaný text. V zabezpečenom režime zostáva celý vstup iba parametrom SELECT.' : 'Dávka SQL sa vykonala, ale UPDATE nenašiel uvedené meno. Žiadne heslo sa nezmenilo.',
      },
    };
  })();
}

export function vulnerableLogin(db, inputs) {
  // INTENTIONALLY VULNERABLE: keep concatenation confined to this demonstration.
  const query = `SELECT id, username, password, role FROM users WHERE username = '${inputs.username}' AND password = '${inputs.password}'`;
  try {
    // All scenarios start with the same SELECT. Only text in the input can
    // introduce a second statement, and the guard limits it to a password update.
    if (PASSWORD_BATCH.test(query)) return executePasswordBatch(db, query, inputs);
    // All other inputs must remain a single read-only statement.
    const statement = db.prepare(query);
    if (!statement.reader || !statement.readonly) throw new Error('Povolený je iba jeden čítací príkaz SELECT.');
    return result(db, 'vulnerable', query, inputs, statement.all());
  } catch (error) {
    const message = error.message.includes('more than one statement')
      ? 'Vstup obsahuje nepovolenú dávku SQL príkazov.'
      : /syntax error|unrecognized token|incomplete input/.test(error.message)
        ? 'SQL príkaz má neplatnú syntax alebo neukončenú textovú hodnotu.'
        : 'Databáza nedokázala vykonať tento SQL príkaz.';
    return result(db, 'vulnerable', query, inputs, [], message);
  }
}

export function secureLogin(db, inputs) {
  const users = db.prepare(SECURE_QUERY).all(inputs.username, inputs.password);
  return result(db, 'secure', SECURE_QUERY, inputs, users);
}
