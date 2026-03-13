export function btn(label, variant = 'secondary') {
  const el = document.createElement('button');
  el.type = 'button';
  el.className = `btn btn-${variant}`;
  el.textContent = label;
  return el;
}

export function input(placeholder = '', type = 'text') {
  const el = document.createElement('input');
  el.type = type;
  el.placeholder = placeholder;
  el.className = 'field';
  return el;
}
