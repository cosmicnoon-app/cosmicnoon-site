// Keep the copyright current; navigation and content work without JavaScript.
document.querySelectorAll('[data-year]').forEach((element) => {
  element.textContent = new Date().getFullYear();
});

// Preserve the old homepage's About and Contact bookmarks.
if (window.location.pathname === '/' || window.location.pathname === '/index.html') {
  const legacyPages = { '#about': '/about/', '#contact': '/contact/' };
  const openLegacyPage = () => {
    const destination = legacyPages[window.location.hash];
    if (destination) window.location.replace(destination);
  };
  openLegacyPage();
  window.addEventListener('hashchange', openLegacyPage);
}
