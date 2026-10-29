# Bezpečnostné laboratórium BIaKS

Lokálna aplikácia k zadaniu 2 predmetu BIaKS. Na skutočnej SQLite databáze demonštruje výpis účtov a hesiel, cielené obídenie prihlasovania a neoprávnenú zmenu hesla. Používa jeden formulár, prepínač Zraniteľný/Zabezpečený a SQL inšpektor.

## Spustenie

Požiadavky: **Node.js 22 alebo novší**, npm a webový prehliadač. V priečinku `zadanie 2 a 4` spustite:

```powershell
npm install
npm start
```

Otvorte **http://localhost:3000** a kliknite na **Otvoriť**. Priamy odkaz: **http://localhost:3000/sql-injection**. Server počúva iba na `127.0.0.1:3000`; ukončíte ho cez `Ctrl+C`. Ak PowerShell blokuje `npm.ps1`, používajte namiesto `npm` príkaz `npm.cmd`.

Databáza `data/sql-injection.sqlite` sa vytvorí automaticky. Obsahuje iba syntetické účty `admin/admin123`, `student/student123` a `guest/guest123`. Čitateľné heslá slúžia výhradne na školskú demonštráciu, nie na produkčné použitie.

## Demonštrácia

1. Vyberte **Zraniteľný**, načítajte **Bežné prihlásenie** a kliknite na **Prihlásiť sa**. Prihlásenie uspeje. **Nesprávne heslo** bude zamietnuté.
2. **Obídenie prihlásenia** po kliknutí na **Prihlásiť sa** vypíše všetky účty vrátane uložených hesiel. **Cielené obídenie prihlásenia** vráti len účet admin a jeho skutočné heslo. `wrong-password` je vstup útočníka; SELECT heslo nemení.
3. **Zmena hesla** vyplní do poľa Používateľské meno celý payload obsahujúci `UPDATE`. Kliknite na rovnaké **Prihlásiť sa**: vložený príkaz zmení heslo účtu student na `changed123`.
4. Na overenie načítajte **Bežné prihlásenie**, zmeňte heslo na `changed123` a prihláste sa ako student. Pôvodné `student123` nebude fungovať, kým nepoužijete reset.
5. Pri každom útoku prepnite na **Zabezpečený** a odošlite rovnaké vstupy. Všetky tri útoky budú odmietnuté. Zabezpečený vždy vykoná iba parametrizovaný prihlasovací SELECT; celý payload je hodnota username.

| Útok | Používateľské meno | Heslo |
| --- | --- | --- |
| Obídenie prihlásenia | `' OR 1=1 --` | `anything` |
| Cielené obídenie prihlásenia | `admin' --` | `wrong-password` |
| Zmena hesla | `'; UPDATE users SET password = 'changed123' WHERE username = 'student'; --` | `anything` |

Karty iba vyplnia formulár. Všetky príklady používajú to isté tlačidlo Prihlásiť sa a ten istý endpoint pre zvolený režim. Backend vždy zostaví rovnaký prihlasovací SELECT. Pri treťom útoku vstup ukončí SELECT bodkočiarkou a pridá vlastný UPDATE; žiadny UPDATE sa nevytvára podľa vybranej karty. Meno aj nové heslo môžete zmeniť priamo v payloade.

Jeden SELECT sa vykoná cez `.all()`. Na dva príkazy SQLite potrebuje `.exec()`, ktorému aplikácia odovzdá presne celý SQL z inšpektora. Laboratórium povoľuje iba obmedzenú dávku pôvodného SELECT a jedného UPDATE hesla v tabuľke users s podmienkou na jedno meno; ostatné zápisy a deštruktívne príkazy odmieta. Inšpektor po dávke ukáže skutočný počet dotknutých riadkov a stav účtov.

## Reset databázy

Použite tlačidlo **Obnoviť databázu** alebo:

```powershell
npm run reset-db
```

Reset obnoví tri pôvodné účty. Bežný reštart servera zachová existujúce údaje.

Zadanie 4 zostáva **Pripravuje sa**;
