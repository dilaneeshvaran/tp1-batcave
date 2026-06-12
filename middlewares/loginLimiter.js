const MAX_ATTEMPTS = 3;
const LOCKOUT_MS = 30 * 1000;

const attempts = {};

function isBlocked(username) {
  const entry = attempts[username];
  if (!entry || !entry.lockedUntil) return { blocked: false, remainingMs: 0 };

  const now = Date.now();
  if (now < entry.lockedUntil) {
    return { blocked: true, remainingMs: entry.lockedUntil - now };
  }

  delete attempts[username];
  return { blocked: false, remainingMs: 0 };
}

function recordFailure(username) {
  if (!attempts[username]) {
    attempts[username] = { count: 0, lockedUntil: null };
  }

  attempts[username].count += 1;

  if (attempts[username].count >= MAX_ATTEMPTS) {
    attempts[username].lockedUntil = Date.now() + LOCKOUT_MS;
  }
}

function recordSuccess(username) {
  delete attempts[username];
}

module.exports = { isBlocked, recordFailure, recordSuccess };
