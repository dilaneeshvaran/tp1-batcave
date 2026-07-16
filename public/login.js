const messageEl = document.getElementById("message");
const credentialsStep = document.getElementById("credentials-step");
const totpStep = document.getElementById("totp-step");
let pendingUsername = "";

function showMessage(text, isError) {
  messageEl.textContent = text || "";
  messageEl.style.color = isError ? "#220100" : "#0a5";
}

document.getElementById("login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  showMessage("");

  const username = document.getElementById("username").value.trim();
  const password = document.getElementById("password").value;

  try {
    const res = await fetch("/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    const data = await res.json().catch(() => ({}));

    if (res.status === 403 && data.twoFactorRequired) {
      showMessage(data.error || "2FA non activee.", true);
      return;
    }

    if (!res.ok) {
      showMessage(data.error || "echec de connexion.", true);
      return;
    }

    if (data.requires2FA) {
      pendingUsername = data.username || username;
      credentialsStep.style.display = "none";
      totpStep.style.display = "block";
      showMessage(data.message || "saisissez votre code 2FA.");
      document.getElementById("totp-code").focus();
      return;
    }

    window.location.href = "/bat-computer";
  } catch (err) {
    showMessage("erreur reseau.", true);
  }
});

document.getElementById("verify-2fa-btn").addEventListener("click", async () => {
  const code = document.getElementById("totp-code").value.trim();
  showMessage("");

  try {
    const res = await fetch("/api/verify-2fa", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: pendingUsername,
        code,
      }),
    });
    const data = await res.json().catch(() => ({}));

    if (!res.ok) {
      showMessage(data.error || "code invalide.", true);
      return;
    }

    window.location.href = "/bat-computer";
  } catch (err) {
    showMessage("erreur reseau.", true);
  }
});
