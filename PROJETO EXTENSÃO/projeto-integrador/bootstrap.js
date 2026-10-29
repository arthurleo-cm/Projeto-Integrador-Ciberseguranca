"use strict";

(() => {
  const loginForm = document.querySelector("#loginForm");
  const mfaForm = document.querySelector("#mfaForm");
  const destination = document.querySelector("#mfaDestination");
  const toast = document.querySelector("#toast");
  let applicationLoading = false;
  let challenge = "";

  function message(text) {
    toast.textContent = text;
    toast.className = "show";
    window.setTimeout(() => (toast.className = ""), 7000);
  }

  async function post(path, body) {
    const response = await fetch("/api" + path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const result = await response.json();
    if (!response.ok)
      throw new Error(result.error || "Não foi possível concluir a operação.");
    return result;
  }

  function loadApplication() {
    if (applicationLoading) return;
    applicationLoading = true;
    const script = document.createElement("script");
    script.src = "/assets/application.js";
    script.addEventListener("error", () => {
      applicationLoading = false;
      message("Não foi possível carregar a área autenticada.");
    });
    document.head.append(script);
  }

  function showMfa(result) {
    challenge = result.desafio;
    destination.textContent = `Enviamos um código para ${result.destino}. Ele expira em 10 minutos.`;
    loginForm.classList.add("hidden");
    mfaForm.classList.remove("hidden");
    mfaForm.elements.codigo.focus();
  }

  function showLogin() {
    challenge = "";
    mfaForm.reset();
    mfaForm.classList.add("hidden");
    loginForm.classList.remove("hidden");
    loginForm.elements.email.focus();
  }

  loginForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = event.submitter;
    if (button) button.disabled = true;
    try {
      const result = await post(
        "/login",
        Object.fromEntries(new FormData(loginForm)),
      );
      loginForm.reset();
      showMfa(result);
    } catch (error) {
      message(error.message);
    } finally {
      if (button) button.disabled = false;
    }
  });

  mfaForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = event.submitter;
    if (button) button.disabled = true;
    try {
      await post("/mfa/verify", {
        desafio: challenge,
        codigo: mfaForm.elements.codigo.value,
      });
      mfaForm.reset();
      loadApplication();
    } catch (error) {
      mfaForm.elements.codigo.select();
      message(error.message);
    } finally {
      if (button) button.disabled = false;
    }
  });

  document.querySelector("#mfaResend").addEventListener("click", async () => {
    const button = document.querySelector("#mfaResend");
    button.disabled = true;
    try {
      const result = await post("/mfa/resend", { desafio: challenge });
      destination.textContent = `Novo código enviado para ${result.destino}.`;
      message("Código reenviado.");
    } catch (error) {
      message(error.message);
    } finally {
      button.disabled = false;
    }
  });
  document.querySelector("#mfaCancel").addEventListener("click", showLogin);

  async function restoreSession() {
    try {
      let response = await fetch("/api/me", {
        headers: { Accept: "application/json" },
        cache: "no-store",
      });
      if (response.status === 401) {
        const refreshed = await post("/refresh", {});
        if (refreshed.csrf)
          response = await fetch("/api/me", {
            headers: { Accept: "application/json" },
            cache: "no-store",
          });
      }
      if (response.ok) loadApplication();
    } catch {
      // A tela de login permanece disponível quando a sessão não pode ser renovada.
    }
  }
  restoreSession();
})();
