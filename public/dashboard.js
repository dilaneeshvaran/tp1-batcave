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
  // if request is for token refresh, use standard fetch to avoid loops
  if (url === "/api/auth/refresh") {
    return fetch(url, options);
  }

  try {
    const response = await fetch(url, options);

    // check if the server transparently refreshed the token and set the custom header
    if (response.headers.get("X-Token-Refreshed") === "true") {
      console.log("refresh de token detecté via entete serveur.");
    }

    if (response.status === 401) {
      console.warn("session expirée (401), tentative de rafraichissement ...");
      if (isRefreshing) {
        // if refreshing is already in progress, queue this request
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
          //  replay initial request
          return fetch(url, options);
        } else {
          console.error("echec du rafraîchissement. eedirection vers la page de connexion.");
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

// expose customFetch to global window object
window.customFetch = customFetch;
