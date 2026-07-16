async function logout() {
  try {
    await fetch("/logout", { method: "POST" });
  } catch (e) {}
  window.location.href = "/auth/login";
}
