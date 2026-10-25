# BIaKS Security Lab

Lokálna aplikácia k zadaniu 2 predmetu BIaKS. Na skutočnej SQLite databáze demonštruje výpis účtov a hesiel, cielené obídenie prihlasovania a neoprávnenú zmenu hesla. Používa jeden formulár, prepínač Vulnerable/Secure a Query Inspector.

## Spustenie

Požiadavky: **Node.js 22 alebo novší**, npm a webový prehliadač. V priečinku `zadanie 2 a 4` spustite:

```powershell
npm install
npm start
```

Otvorte **http://localhost:3000** a kliknite na **Launch Lab**. Priamy odkaz: **http://localhost:3000/sql-injection**. Server počúva iba na `127.0.0.1:3000`; ukončíte ho cez `Ctrl+C`. Ak PowerShell blokuje `npm.ps1`, používajte namiesto `npm` príkaz `npm.cmd`.

Databáza `data/sql-injection.sqlite` sa vytvorí automaticky. Obsahuje iba syntetické účty `admin/admin123`, `student/student123` a `guest/guest123`. Čitateľné heslá slúžia výhradne na školskú demonštráciu, nie na produkčné použitie.

## Demonštrácia

1. Vyberte **Vulnerable**, načítajte **Normal login** a kliknite na **Login**. Prihlásenie uspeje. **Wrong password** bude zamietnuté.
2. **Authentication bypass** po kliknutí na **Login** vypíše všetky účty vrátane uložených hesiel. **Targeted account bypass** vráti len účet admin a jeho skutočné heslo. `wrong-password` je vstup útočníka; SELECT heslo nemení.
3. **Password change** vyplní do Username celý payload obsahujúci `UPDATE`. Kliknite na rovnaké **Login**: vložený príkaz zmení heslo účtu student na `changed123`.
4. Na overenie načítajte **Normal login**, zmeňte heslo na `changed123` a prihláste sa ako student. Pôvodné `student123` nebude fungovať, kým nepoužijete reset.
5. Pri každom útoku prepnite na **Secure** a odošlite rovnaké vstupy. Všetky tri útoky budú odmietnuté. Secure vždy vykoná iba parametrizovaný prihlasovací SELECT; celý payload je hodnota username.

| Útok | Username | Password |
| --- | --- | --- |
| Authentication bypass | `' OR 1=1 --` | `anything` |
| Targeted account bypass | `admin' --` | `wrong-password` |
| Password change | `'; UPDATE users SET password = 'changed123' WHERE username = 'student'; --` | `anything` |

Karty iba vyplnia formulár. Všetky príklady používajú ten istý Login a ten istý endpoint pre zvolený režim. Backend vždy zostaví rovnaký prihlasovací SELECT. Pri treťom útoku vstup ukončí SELECT bodkočiarkou a pridá vlastný UPDATE; žiadny UPDATE sa nevytvára podľa vybranej karty. Meno aj nové heslo môžete zmeniť priamo v payloade.

Jeden SELECT sa vykoná cez `.all()`. Na dva príkazy SQLite potrebuje `.exec()`, ktorému aplikácia odovzdá presne celý SQL z inspectora. Laboratórium povoľuje iba obmedzenú dávku pôvodného SELECT a jedného UPDATE hesla v tabuľke users s podmienkou na jedno username; ostatné zápisy a deštruktívne príkazy odmieta. Inspector po dávke ukáže skutočný počet dotknutých riadkov a stav účtov.

## Reset databázy

Použite tlačidlo **Reset database** alebo:

```powershell
npm run reset-db
```

Reset obnoví tri pôvodné účty. Bežný reštart servera zachová existujúce údaje.

Zadanie 4 zostáva **Coming Soon**;