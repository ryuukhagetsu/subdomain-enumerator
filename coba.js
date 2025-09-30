(function(){
  const d = document.createElement('div');
  d.id = 'xss-poc-banner';
  d.textContent = '[XSS PoC] Executed on ' + location.href;
  d.style.position = 'fixed';
  d.style.top = '0';
  d.style.left = '0';
  d.style.right = '0';
  d.style.background = 'red';
  d.style.color = 'white';
  d.style.fontSize = '16px';
  d.style.zIndex = '2147483647';
  d.style.padding = '8px';
  document.body.appendChild(d);
  console.log('[XSS PoC] banner appended');
})();
