document.getElementById("register-form").onsubmit = async (e) => {
  e.preventDefault();
  const username = document.getElementById("username").value;
  const password = document.getElementById("password").value;

  const response = await fetch("/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });

  const messageElement = document.getElementById("message");
  if (response.ok) {
    messageElement.style.color = "green";
    messageElement.innerText = "Inscription réussie ! Redirection en cours...";
    setTimeout(() => (window.location.href = "bat-computer"), 2000);
  } else {
    const errorMessage = await response.text();
    messageElement.style.color = "red";
    messageElement.innerText = errorMessage || "Erreur lors de l'inscription.";
  }
};
