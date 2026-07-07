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

    if (response.status === 401) {
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
          isRefreshing = false;
          processQueue(null);
          //  replay initial request
          return fetch(url, options);
        } else {
          isRefreshing = false;
          processQueue(new Error("Refresh failed"));
          window.location.href = "/auth/login";
          return response;
        }
      } catch (refreshErr) {
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
