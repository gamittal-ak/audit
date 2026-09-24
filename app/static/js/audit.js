/* Navigation and search operate only on the collected report. */
window.AuditUI = (() => {
  'use strict';
  let root, properties = [], groups = [], snapshot = null, tlsFilter = 'all', observer = null;
  const byId = id => document.getElementById(id);
  const fold = value => String(value ?? '').toLocaleLowerCase();
  const tokens = value => fold(value).trim().split(/\s+/).filter(Boolean);
  const matches = (value, words) => words.every(word => fold(value).includes(word));
  function showTab(id) {
    const el = byId(id);
    if (el?.dataset.scrollTarget) byId(el.dataset.scrollTarget)?.scrollIntoView({block:'start',behavior:'smooth'});
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
    const cert = byId('propCertificate')?.value || '';
    const scopeNetwork = byId('tlsNetwork')?.value || 'PRODUCTION';
    const networks = scopeNetwork === 'BOTH' ? ['PRODUCTION','STAGING'] : [scopeNetwork];
    const selectedSecurity = item => networks.map(n => item.security[n]).filter(Boolean);
    const isTLSMatch = (item,key) => {
      if (key === 'all') return true;
      return selectedSecurity(item).some(s => s.status !== 'inactive' && (
        key === 'shared' ? s.certificate_types.includes('Akamai shared') :
        key === 'Mixed' ? s.label.startsWith('Mixed') : s.modes.includes(key)));
    };
    root.querySelectorAll('[data-tls-count]').forEach(el => {
      el.textContent = properties.filter(item => isTLSMatch(item,el.dataset.tlsCount)).length;
    });
    root.querySelectorAll('[data-tls-filter]').forEach(el => {
      const pressed = el.dataset.tlsFilter === tlsFilter;
      el.classList.toggle('is-active',pressed); el.setAttribute('aria-pressed',String(pressed));
    });
    const active = !!(words.length || selectedGroup || finding || cert || tlsFilter !== 'all');
    if (active && !snapshot) {
      snapshot = {
        groups: groups.map(el => [el, el.querySelector('.accordion-collapse').classList.contains('show')]),
        properties: properties.map(item => [item.el, item.el.open, null])
      };
    }
    let count = 0, groupCount = 0;
    properties.forEach(item => {
      const fields = item.fields.filter(f => !scope || f.label === scope);
      const match = matches(fields.map(f => f.value).join(' '), words);
      const visible = match && (!selectedGroup || item.group.dataset.groupIndex === selectedGroup) && isTLSMatch(item,tlsFilter)
        && (!cert || selectedSecurity(item).some(s => s.certificate_types.includes(cert)))
        && (!finding || (finding === 'edge' ? item.el.dataset.edgeWarning === 'true' :
          selectedSecurity(item).some(s => s.status !== 'inactive' &&
            (!s.hostnames.length || s.hostnames.some(h => h.protocol === 'Unknown' || h.protocol.includes('unknown'))))));
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
      group.hidden = active ? !visible && !(selectedGroup === group.dataset.groupIndex && !words.length && !finding && !cert && tlsFilter === 'all') : false;
      if (!group.hidden) groupCount++;
      if (active && !group.hidden) setGroup(group, true);
    });
    if (!active && snapshot) {
      snapshot.groups.forEach(([el, open]) => setGroup(el, open));
      snapshot.properties.forEach(([el, open, tab]) => { el.open = open;  });
      snapshot = null;
    }
    byId('propSearchClear').hidden = !active;
    byId('noResultsMsg').hidden = count > 0 || (!active && groups.length > 0);
    byId('property-result-count').textContent = active
      ? count + ' of ' + properties.length + ' properties · ' + groupCount + ' groups'
      : properties.length + ' properties across ' + groups.length + ' groups · Open a property to inspect its data';
  }
  function setTLSFilter(value) { tlsFilter = value; filterProperties(); }
  function sortProperties() {
    const sort = byId('propSort')?.value || 'name';
    groups.forEach(group => {
      const items = properties.filter(item => item.group === group);
      items.sort((a,b) => sort === 'name'
        ? a.el.dataset.name.localeCompare(b.el.dataset.name,undefined,{numeric:true,sensitivity:'base'})
        : Number(b.el.dataset[sort]) - Number(a.el.dataset[sort]) || a.el.dataset.name.localeCompare(b.el.dataset.name));
      const body = group.querySelector('.accordion-body');
      items.forEach(item => body.append(item.el));
    });
  }
  function resetProperties() {
    tlsFilter = 'all';
    ['propSearch','propSearchScope','propGroup','propFinding','propCertificate'].forEach(id => { byId(id).value = ''; });
    filterProperties(); byId('propSearch').focus();
  }
  function showEdgeWarnings() {
    showTab('properties-tab'); resetProperties(); byId('propFinding').value = 'edge'; filterProperties();
    byId('properties-panel').scrollIntoView({block:'start', behavior:'smooth'});
  }
  function showOrigins(view) {
    showTab('origin-' + view + '-tab');
    const panel = byId('origin-' + view);
    if (panel) { panel.querySelector('.origin-search').value = ''; panel.querySelector('.origin-filter').value = ''; filterOrigins(panel); }

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
    root.dataset.initialized = 'true'; snapshot = null; tlsFilter = 'all';
    groups = [...root.querySelectorAll('[data-group-index]')];
    groups.forEach(group => setGroup(group,group.querySelector('.accordion-collapse').classList.contains('show')));
    properties = [...root.querySelectorAll('[data-property]')].map(el => {
      const security = JSON.parse(el.dataset.security || '{}');
      ['PRODUCTION','STAGING'].forEach(n => {
        if (!security[n]) security[n] = {status:'not_collected',label:'Unknown',modes:['Unknown'],certificate_types:['Unknown'],hostnames:[]};
      });
      const item = {el, security, fields:JSON.parse(el.dataset.fields), group:el.closest('[data-group-index]')};
      el.addEventListener('toggle', () => { if (el.open) revealProperty(item); });
      return item;
    });
    root.querySelectorAll('[data-origin-row]').forEach(row => { row.dataset.searchText = row.textContent; });
    root.querySelectorAll('.origin-panel').forEach(filterOrigins);
    root.querySelectorAll('.table-responsive').forEach(el => { el.setAttribute('tabindex','0'); });
    sortableTables(); filterProperties();
    if (observer) observer.disconnect();
    observer = new IntersectionObserver(entries => {
      entries.forEach(entry => {
        if (!entry.isIntersecting) return;
        root.querySelectorAll('.section-link').forEach(link => {
          const active = link.dataset.scrollTarget === entry.target.id;
          link.classList.toggle('active',active);
          if (active) link.setAttribute('aria-current','location'); else link.removeAttribute('aria-current');
        });
      });
    }, {rootMargin:'-55px 0px -65% 0px'});
    root.querySelectorAll('.report-panel').forEach(panel => observer.observe(panel));
    sortProperties();
    byId('propSearch').addEventListener('keydown', event => { if (event.key === 'Escape') resetProperties(); });
  }
  return {initReport,setTLSFilter,sortProperties,filterProperties,resetProperties,showEdgeWarnings,showOrigins,expandGroups,filterOrigins,resetOrigins};
})();
