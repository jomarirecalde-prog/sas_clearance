(() => {
  const config = window.STUDENT_PWA || {};
  const installButtons = () => Array.from(document.querySelectorAll("[data-sapp-install]"));
  const banners = () => Array.from(document.querySelectorAll("[data-sapp-install-banner]"));
  const iosHelp = document.querySelector("[data-sapp-ios-help]");

  function isStandalone() {
    return window.matchMedia("(display-mode: standalone)").matches
      || window.matchMedia("(display-mode: minimal-ui)").matches
      || window.navigator.standalone === true;
  }

  function isIos() {
    return /iphone|ipad|ipod/i.test(window.navigator.userAgent)
      || (window.navigator.platform === "MacIntel" && window.navigator.maxTouchPoints > 1);
  }

  function markInstalled() {
    document.body.classList.add("sapp-installed");
    banners().forEach((el) => el.classList.remove("is-visible"));
    installButtons().forEach((btn) => btn.classList.remove("is-visible"));
    if (iosHelp) iosHelp.hidden = true;
  }

  function showIosHelp() {
    banners().forEach((el) => el.classList.add("is-visible"));
    if (iosHelp) iosHelp.hidden = false;
  }

  if (isStandalone()) {
    markInstalled();
  } else if (isIos()) {
    showIosHelp();
  }

  if ("serviceWorker" in navigator && config.swUrl) {
    window.addEventListener("load", () => {
      navigator.serviceWorker.register(config.swUrl, { scope: config.scope || "/" }).catch(() => {});
    });
  }

  let deferredPrompt = null;
  window.addEventListener("beforeinstallprompt", (event) => {
    event.preventDefault();
    deferredPrompt = event;
    if (isStandalone()) return;
    installButtons().forEach((btn) => btn.classList.add("is-visible"));
    banners().forEach((el) => el.classList.add("is-visible"));
    if (iosHelp) iosHelp.hidden = true;
  });

  window.addEventListener("appinstalled", () => {
    deferredPrompt = null;
    markInstalled();
  });

  document.addEventListener("click", async (event) => {
    const btn = event.target.closest("[data-sapp-install]");
    if (!btn) return;
    if (isIos() && !deferredPrompt) {
      showIosHelp();
      return;
    }
    if (!deferredPrompt) return;
    deferredPrompt.prompt();
    await deferredPrompt.userChoice;
    deferredPrompt = null;
  });
})();
