function logout() {
  fetch("/api/logout", {
    method: "POST",
    headers: { Authorization: "Basic logout:logout" },
  })
    .then(() => {
      window.location.href = "/";
    })
    .catch((error) => {
      console.error("Error during logout:", error);
    });
}
