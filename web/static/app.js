'use strict';
const toast = document.querySelector('#copy-status');
let timer;
for (const button of document.querySelectorAll('[data-copy]')) {
  button.addEventListener('click', async () => {
    let message;
    try {
      if (!navigator.clipboard) throw new Error('Clipboard unavailable');
      await navigator.clipboard.writeText(button.dataset.copy);
      message = 'Copied to clipboard.';
    } catch { message = 'Could not copy. Select the value and copy it manually.'; }
    toast.textContent = message; toast.classList.add('visible');
    clearTimeout(timer); timer = setTimeout(() => toast.classList.remove('visible'), 4500);
  });
}
for (const button of document.querySelectorAll('[data-confirm]')) {
  button.addEventListener('click', event => { if (!window.confirm(button.dataset.confirm)) event.preventDefault(); });
}
document.addEventListener('keydown', event => {
  if (event.key === 'Escape') {
    for (const menu of document.querySelectorAll('.account-menu[open], .header-search[open]')) { menu.open = false; menu.querySelector('summary').focus(); }
  }
});
const tokenInput = document.querySelector('#redemption-token');
if (tokenInput) {
  const token = new URLSearchParams(location.search).get('token');
  if (token) { tokenInput.value = token; history.replaceState(null, '', '/account/redeem'); }
}
const editor = document.querySelector('#service-editor');
if (editor) {
  const portalFields = document.querySelector('#external-portal-fields');
  const showPortal = () => { if (portalFields) portalFields.hidden = editor.elements.mode.value !== 'external'; };
  editor.elements.mode.addEventListener('change', showPortal); showPortal();
  const update = () => {
    document.querySelector('#preview-name').textContent = editor.elements.name.value || 'Your service';
    document.querySelector('#preview-art-title').textContent = editor.elements.name.value || 'Your service';
    document.querySelector('#preview-summary').textContent = editor.elements.summary.value || 'A place worth sharing.';
    const image = document.querySelector('#preview-image');
    const raw = editor.elements.artwork.value;
    let valid = raw.startsWith('/media/');
    try { const url = new URL(raw); valid ||= ['http:', 'https:'].includes(url.protocol) && !url.username && !url.password; } catch {}
    image.hidden = !valid;
    if (valid && image.getAttribute('src') !== raw) image.src = raw;
    image.style.objectPosition = `${editor.elements.focal_x.value}% ${editor.elements.focal_y.value}%`;
  };
  editor.addEventListener('input', update); update();
}
for (const img of document.querySelectorAll('.artwork img')) {
  img.addEventListener('error', () => { img.hidden = true; });
}
for (const link of document.querySelectorAll('.filters a')) {
  const selected = new URLSearchParams(location.search).get('category') || '';
  const category = new URL(link.href).searchParams.get('category') || '';
  if (category === selected) link.setAttribute('aria-current', 'page'); else link.removeAttribute('aria-current');
}

for (const select of document.querySelectorAll('select[name="placement"]')) {
  const update = () => { for (const field of select.form.querySelectorAll('[data-parent]')) field.hidden = field.dataset.parent !== select.value; };
  select.addEventListener('change', update); update();
}

for (const form of document.querySelectorAll('form[method="post"]:not([data-download])')) {
  form.addEventListener('submit', () => { form.setAttribute('aria-busy', 'true'); document.body.classList.add('navigating'); });
}
window.addEventListener('pageshow', () => {
  document.body.classList.remove('navigating');
  for (const form of document.querySelectorAll('form[aria-busy]')) form.removeAttribute('aria-busy');
});
