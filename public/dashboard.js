let isRefreshing = false;
let failedQueue = [];

const processQueue = (error) => {
  failedQueue.forEach((prom) => {
    if (error) {
      prom.reject(error);
    } else {
      prom.resolve();
    }
  });
  failedQueue = [];
};

async function customFetch(url, options = {}) {
  if (url === "/api/auth/refresh") {
    return fetch(url, options);
  }

  try {
    const response = await fetch(url, options);

    if (response.status === 401) {
      console.warn("session expirée (401), tentative de rafraichissement ...");
      if (isRefreshing) {
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject });
        })
          .then(() => {
            return fetch(url, options);
          })
          .catch((err) => {
            return Promise.reject(err);
          });
      }

      isRefreshing = true;

      try {
        const refreshResponse = await fetch("/api/auth/refresh", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
        });

        if (refreshResponse.ok) {
          console.log("token rafraîchi avec succès. replay initial request");
          isRefreshing = false;
          processQueue(null);
          return fetch(url, options);
        } else {
          console.error("echec du rafraîchissement. redirection vers la page de connexion.");
          isRefreshing = false;
          processQueue(new Error("Refresh failed"));
          window.location.href = "/auth/login";
          return response;
        }
      } catch (refreshErr) {
        console.error("erreur lors du rafraichissement:", refreshErr);
        isRefreshing = false;
        processQueue(refreshErr);
        window.location.href = "/auth/login";
        throw refreshErr;
      }
    }

    return response;
  } catch (error) {
    throw error;
  }
}

window.customFetch = customFetch;
