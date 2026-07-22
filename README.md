# TP1 et TP2

TP1 est sur la branche tp1
TP2 est sur la branche tp2
TP3 est sur la branche tp3
TP4 est sur la branche tp4
TP5 est sur la branche tp5

## How to start

```bash
npm install
npm start
```

Then open http://localhost:3000 in your browser.

## test admin panel (to see logs and change user roles)

1. create a normal account at `/register`.
2. open your sqlite database tool and execute:

   ```sql
   UPDATE users SET role = 'ADMIN' WHERE username = 'your_username';
   ```

   Alternatively, run this directly in terminal:

   ```bash
   node -e "require('./db').prepare('UPDATE users SET role = ? WHERE username = ?').run('ADMIN', 'your_username')"
   ```

---

By Dilan EESHVARAN 4iw1
