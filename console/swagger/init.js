"use strict";

// Swagger UI 5.17.14 (swagger-ui-dist, Apache-2.0; see LICENSE) over the
// console's OpenAPI document. Requests go out with the console's session
// cookie and its CSRF header, so "Try it out" works for a signed-in page
// without a token. "Authorize" sets X-API-Token instead, as a script would.
window.addEventListener("DOMContentLoaded", () => {
  window.ui = SwaggerUIBundle({
    url: "../openapi.json",
    dom_id: "#swagger-ui",
    deepLinking: true,
    tryItOutEnabled: true,
    displayRequestDuration: true,
    persistAuthorization: false,
    defaultModelsExpandDepth: 0,
    requestInterceptor: (req) => {
      req.headers["X-PF-Console"] = "1";
      return req;
    },
  });
});
