# How to start

```bash
npm install
npm start
```

Then open http://localhost:3000 in your browser.

## test admin panel

1. create a normal account at `/register`.
2. open your sqlite database tool and execute:
   ```sql
   UPDATE users SET role = 'ADMIN' WHERE username = 'your_username';
   ```
   _(Alternatively, run this directly in terminal: `node -e "require('./db').prepare(\"UPDATE users SET role = 'ADMIN' WHERE username = 'your_username'\").run()"`)_

---

By Dilan EESHVARAN 4iw1
