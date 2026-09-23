(() => {
  let taskId = null;
  let follow = true;
  let snapshot = null;
  const output = () => document.getElementById('audit-log-output');
  const button = () => document.getElementById('audit-log-follow');
  function syncButton() {
    const control = button();
    if (!control) return;
    control.setAttribute('aria-pressed', String(follow));
    control.textContent = follow ? 'Auto-scroll on' : 'Follow latest';
  }
  function initialize() {
    const panel = document.querySelector('[data-audit-terminal]');
    const log = output();
    if (!panel || !log || log.dataset.initialized) return;
    log.dataset.initialized = 'true';
    if (panel.dataset.taskId !== taskId) {
      taskId = panel.dataset.taskId;
      follow = true;
      snapshot = null;
    }
    if (follow) log.scrollTop = log.scrollHeight;
    else if (snapshot) {
      const anchor = Array.from(log.children).find(line => line.dataset.logId === snapshot.id);
      log.scrollTop = anchor ? anchor.offsetTop - log.offsetTop - snapshot.offset : snapshot.top;
    }
    syncButton();
    if (snapshot?.focus) document.getElementById(snapshot.focus)?.focus({preventScroll: true});
    log.addEventListener('scroll', () => {
      follow = log.scrollHeight - log.clientHeight - log.scrollTop < 16;
      syncButton();
    }, {passive: true});
    button().addEventListener('click', () => {
      follow = !follow;
      if (follow) log.scrollTop = log.scrollHeight;
      syncButton();
    });
  }
  document.addEventListener('htmx:beforeSwap', event => {
    if (event.detail.target?.id !== 'report-content') return;
    const log = output();
    if (!log) return;
    const anchor = Array.from(log.children).find(line => line.offsetTop - log.offsetTop + line.offsetHeight > log.scrollTop);
    const focused = document.activeElement;
    snapshot = {
      top: log.scrollTop, id: anchor?.dataset.logId,
      offset: anchor ? anchor.offsetTop - log.offsetTop - log.scrollTop : 0,
      focus: focused === log || focused === button() ? focused.id : null,
    };
  });
  document.addEventListener('htmx:afterSwap', initialize);
  initialize();
})();
