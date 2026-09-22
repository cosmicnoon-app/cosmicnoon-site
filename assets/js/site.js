// Keep the copyright current; navigation and content work without JavaScript.
document.querySelectorAll('[data-year]').forEach((element) => {
  element.textContent = new Date().getFullYear();
});

// A native disclosure keeps project navigation usable without JavaScript.
document.querySelectorAll('.projects-menu').forEach((menu) => {
  const trigger = menu.querySelector('summary');
  const links = Array.from(menu.querySelectorAll('a'));

  document.addEventListener('click', (event) => {
    if (!menu.contains(event.target)) menu.open = false;
  });

  menu.addEventListener('focusout', (event) => {
    if (!menu.contains(event.relatedTarget)) menu.open = false;
  });

  menu.addEventListener('click', (event) => {
    if (event.target.closest('a')) {
      menu.open = false;
      trigger.focus({ preventScroll: true });
    }
  });

  menu.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && menu.open) {
      event.preventDefault();
      menu.open = false;
      trigger.focus();
      return;
    }
    if (!['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) return;
    if (!menu.open && event.key !== 'ArrowDown' && event.key !== 'ArrowUp') return;
    event.preventDefault();
    menu.open = true;
    const current = links.indexOf(document.activeElement);
    let next;
    if (event.key === 'Home') next = 0;
    else if (event.key === 'End') next = links.length - 1;
    else if (event.key === 'ArrowDown') next = (current + 1) % links.length;
    else next = current <= 0 ? links.length - 1 : current - 1;
    links[next].focus();
  });
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
