/* Navigation and search operate only on the collected report. */
window.AuditUI = (() => {
  'use strict';
  let root, properties = [], groups = [], snapshot = null;
  const byId = id => document.getElementById(id);
  const fold = value => String(value ?? '').toLocaleLowerCase();
  const tokens = value => fold(value).trim().split(/\s+/).filter(Boolean);
  const matches = (value, words) => words.every(word => fold(value).includes(word));
  function showTab(id) {
    const el = byId(id);
    if (el) bootstrap.Tab.getOrCreateInstance(el).show();
  }
  function setGroup(group, open) {
    const body = group.querySelector('.accordion-collapse');
    const button = group.querySelector('.accordion-button');
    body.classList.toggle('show', open);
    button.classList.toggle('collapsed', !open);
    button.setAttribute('aria-expanded', String(open));
    button.setAttribute('aria-controls', body.id);
  }
  function removeHighlights(el) {
    el.querySelectorAll('mark.search-highlight').forEach(mark => mark.replaceWith(document.createTextNode(mark.textContent)));
    el.normalize();
  }
  function highlight(el, words) {
    if (!el) return;
    removeHighlights(el);
    if (!words.length) return;
    const escape = word => word.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const pattern = new RegExp('(' + [...words].sort((a,b) => b.length-a.length).map(escape).join('|') + ')', 'gi');
    const walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT);
    const nodes = [];
    while (walker.nextNode()) {
      if (!walker.currentNode.parentElement.closest('script,style,button,select')) nodes.push(walker.currentNode);
    }
    nodes.forEach(node => {
      const parts = node.textContent.split(pattern);
      if (parts.length < 2) return;
      const fragment = document.createDocumentFragment();
      parts.forEach((part,i) => {
        if (i % 2) { const mark = document.createElement('mark'); mark.className = 'search-highlight'; mark.textContent = part; fragment.append(mark); }
        else fragment.append(document.createTextNode(part));
      });
      node.replaceWith(fragment);
    });
  }
  function revealProperty(item) {
    const words = tokens(byId('propSearch').value);
    const field = item.match;
    if (words.length && field?.tab) {
      const tab = item.el.querySelector('[data-bs-target$="-' + field.tab + '"]');
      if (tab) bootstrap.Tab.getOrCreateInstance(tab).show();
    }
    item.el.querySelectorAll('tbody tr').forEach(row => {
      row.classList.toggle('matched-row', !!words.length && words.some(word => fold(row.textContent).includes(word)));
    });
    highlight(item.el.querySelector('.property-body'), words);
  }
  function filterProperties() {
    if (!root) return;
    const words = tokens(byId('propSearch').value);
    const scope = byId('propSearchScope').value;
    const selectedGroup = byId('propGroup').value;
    const finding = byId('propFinding').value;
    const active = !!(words.length || selectedGroup || finding);
    if (active && !snapshot) {
      snapshot = {
        groups: groups.map(el => [el, el.querySelector('.accordion-collapse').classList.contains('show')]),
        properties: properties.map(item => [item.el, item.el.open, item.el.querySelector('[data-bs-toggle="tab"].active')])
      };
    }
    let count = 0, groupCount = 0;
    properties.forEach(item => {
      const fields = item.fields.filter(f => !scope || f.label === scope);
      const match = matches(fields.map(f => f.value).join(' '), words);
      const visible = match && (!selectedGroup || item.group.dataset.groupIndex === selectedGroup) && (!finding || item.el.dataset.edgeWarning === 'true');
      item.el.hidden = !visible;
      item.match = words.length ? fields.find(f => words.some(word => fold(f.value).includes(word))) : null;
      const hint = item.el.querySelector('.property-match');
      hint.hidden = !visible || !words.length;
      hint.textContent = item.match ? item.match.label + ': ' + item.match.value : '';
      if (!hint.hidden) highlight(hint, words);
      highlight(item.el.querySelector('.property-name'), visible ? words : []);
      if (visible) count++;
      if (item.el.open) revealProperty(item);
    });
    groups.forEach(group => {
      const visible = [...group.querySelectorAll('[data-property]')].some(el => !el.hidden);
      // Empty groups remain available when there is no property search.
      group.hidden = active ? !visible && !(selectedGroup === group.dataset.groupIndex && !words.length && !finding) : false;
      if (!group.hidden) groupCount++;
      if (active && !group.hidden) setGroup(group, true);
    });
    if (!active && snapshot) {
      snapshot.groups.forEach(([el, open]) => setGroup(el, open));
      snapshot.properties.forEach(([el, open, tab]) => { el.open = open; if (tab) bootstrap.Tab.getOrCreateInstance(tab).show(); });
      snapshot = null;
    }
    byId('propSearchClear').hidden = !active;
    byId('noResultsMsg').hidden = count > 0 || (!active && groups.length > 0);
    byId('property-result-count').textContent = active
      ? count + ' of ' + properties.length + ' properties · ' + groupCount + ' groups'
      : properties.length + ' properties across ' + groups.length + ' groups · Open a property to inspect its data';
  }
  function resetProperties() {
    ['propSearch','propSearchScope','propGroup','propFinding'].forEach(id => { byId(id).value = ''; });
    filterProperties(); byId('propSearch').focus();
  }
  function showEdgeWarnings() {
    showTab('properties-tab'); resetProperties(); byId('propFinding').value = 'edge'; filterProperties();
    byId('properties-tab').scrollIntoView({block:'start', behavior:'smooth'});
  }
  function showOrigins(view) {
    showTab('origins-tab'); showTab('origin-' + view + '-tab');
    const panel = byId('origin-' + view);
    if (panel) { panel.querySelector('.origin-search').value = ''; panel.querySelector('.origin-filter').value = ''; filterOrigins(panel); }
    byId('origins-tab').scrollIntoView({block:'start', behavior:'smooth'});
  }
  function expandGroups(open) { groups.filter(group => !group.hidden).forEach(group => setGroup(group, open)); }
  function filterOrigins(control) {
    const panel = control.closest('.origin-panel');
    const words = tokens(panel.querySelector('.origin-search').value);
    const status = panel.querySelector('.origin-filter').value;
    const rows = [...panel.querySelectorAll('[data-origin-row]')];
    let count = 0;
    rows.forEach(row => {
      row.hidden = !matches(row.dataset.searchText || row.textContent, words) || (!!status && row.dataset.status !== status);
      if (!row.hidden) count++;
    });
    panel.querySelector('.origin-result-count').textContent = count + ' of ' + rows.length + ' rows' + (words.length || status ? ' · filtered' : '');
    const empty = panel.querySelector('.origin-no-match');
    if (empty) empty.hidden = count > 0;
  }
  function resetOrigins(control) {
    const panel = control.closest('.origin-panel');
    panel.querySelector('.origin-search').value = '';
    panel.querySelector('.origin-filter').value = '';
    filterOrigins(panel); panel.querySelector('.origin-search').focus();
  }
  function sortableTables() {
    root.querySelectorAll('.origin-panel table').forEach(table => {
      table.querySelectorAll('thead th').forEach((th,index) => {
        const label = th.textContent.trim();
        th.textContent = '';
        const button = document.createElement('button');
        button.type = 'button'; button.className = 'table-sort'; button.textContent = label + ' ↕';
        button.setAttribute('aria-label','Sort by ' + label);
        th.append(button); th.setAttribute('aria-sort','none');
        button.addEventListener('click', () => {
          const asc = th.getAttribute('aria-sort') !== 'ascending';
          table.querySelectorAll('th').forEach(cell => cell.setAttribute('aria-sort','none'));
          th.setAttribute('aria-sort', asc ? 'ascending' : 'descending');
          const rows = [...table.tBodies[0].rows];
          rows.sort((a,b) => {
            const x = a.cells[index].textContent.trim(), y = b.cells[index].textContent.trim();
            const comparison = x && y && Number.isFinite(Number(x)) && Number.isFinite(Number(y))
              ? Number(x)-Number(y) : x.localeCompare(y,undefined,{numeric:true,sensitivity:'base'});
            return asc ? comparison : -comparison;
          });
          rows.forEach(row => table.tBodies[0].append(row));
        });
      });
    });
  }
  function initReport() {
    root = byId('report-content');
    if (!root?.dataset.reportId || root.dataset.initialized) return;
    root.dataset.initialized = 'true'; snapshot = null;
    groups = [...root.querySelectorAll('[data-group-index]')];
    groups.forEach(group => setGroup(group,group.querySelector('.accordion-collapse').classList.contains('show')));
    properties = [...root.querySelectorAll('[data-property]')].map(el => {
      const item = {el, fields:JSON.parse(el.dataset.fields), group:el.closest('[data-group-index]')};
      el.addEventListener('toggle', () => { if (el.open) revealProperty(item); });
      return item;
    });
    root.querySelectorAll('[data-origin-row]').forEach(row => { row.dataset.searchText = row.textContent; });
    root.querySelectorAll('.origin-panel').forEach(filterOrigins);
    root.querySelectorAll('.table-responsive').forEach(el => { el.setAttribute('tabindex','0'); });
    sortableTables(); filterProperties();
    root.addEventListener('shown.bs.tab', event => {
      if (event.target.id === 'traffic-tab' && window.Chart) {
        root.querySelectorAll('#traffic-panel canvas').forEach(canvas => Chart.getChart(canvas)?.resize());
      }
    });
    byId('propSearch').addEventListener('keydown', event => { if (event.key === 'Escape') resetProperties(); });
  }
  return {initReport,filterProperties,resetProperties,showEdgeWarnings,showOrigins,expandGroups,filterOrigins,resetOrigins};
})();
