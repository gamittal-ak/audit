window.HistoryUI = (() => {
  'use strict';
  const selected = new Set();
  let pending = [], deleting = false, savedFocus = null;
  const byId = id => document.getElementById(id);
  const rows = () => [...document.querySelectorAll('.task-item')];
  const visibleRows = () => rows().filter(row => !row.hidden);
  const eligibleRows = () => visibleRows().filter(row => !row.querySelector('.task-cb').disabled);
  const read = key => { try { return sessionStorage.getItem(key) || ''; } catch { return ''; } };
  const write = (key,value) => { try { sessionStorage.setItem(key,value); } catch {} };
  function applyFilters() {
    if (!byId('filter-account')) return;
    const account = byId('filter-account').value.toLocaleLowerCase();
    const status = byId('filter-status').value;
    const grouping = byId('group-by').value;
    document.querySelectorAll('.group-header').forEach(el => el.remove());
    const container = byId('task-items');
    const items = rows().sort((a,b) => b.dataset.date.localeCompare(a.dataset.date));
    items.forEach(row => {
      row.hidden = !row.dataset.account.toLocaleLowerCase().includes(account) || (!!status && row.dataset.status !== status);
      container.append(row);
    });
    if (grouping) {
      const grouped = new Map();
      items.filter(row => !row.hidden).forEach(row => {
        const key = grouping === 'account' ? row.dataset.account : grouping === 'date' ? row.dataset.date.split(' ')[0] : row.dataset.status;
        if (!grouped.has(key)) grouped.set(key, []);
        grouped.get(key).push(row);
      });
      [...grouped.keys()].sort((a,b) => grouping === 'date' ? b.localeCompare(a) : a.localeCompare(b)).forEach(key => {
        const heading = document.createElement('div'); heading.className = 'group-header';
        heading.textContent = ({SUCCESS:'Complete',PROGRESS:'Running',FAILURE:'Failed',PENDING:'Queued',REVOKED:'Cancelled'})[key] || key;
        container.append(heading); grouped.get(key).forEach(row => container.append(row));
      });
    }
    byId('no-match').hidden = visibleRows().length > 0;
    syncSelection();
  }
  function syncSelection() {
    const eligible = eligibleRows();
    const valid = new Set(eligible.map(row => row.dataset.taskId));
    [...selected].forEach(id => { if (!valid.has(id)) selected.delete(id); });
    rows().forEach(row => {
      const checked = selected.has(row.dataset.taskId);
      row.querySelector('.task-cb').checked = checked; row.classList.toggle('is-selected',checked);
    });
    if (!byId('select-all')) return;
    byId('select-all').checked = eligible.length > 0 && selected.size === eligible.length;
    byId('select-all').indeterminate = selected.size > 0 && selected.size < eligible.length;
    byId('select-all').disabled = eligible.length === 0;
    byId('selection-actions').hidden = !selected.size;
    byId('btn-delete-sel').textContent = 'Delete selected (' + selected.size + ')';
    byId('history-count').textContent = selected.size ? selected.size + ' selected' : visibleRows().length + ' shown';
  }
  function restore() {
    [['filter-account','tl_acct'],['filter-status','tl_status'],['group-by','tl_groupby']].forEach(([id,key]) => { if (byId(id)) byId(id).value = read(key); });
    applyFilters();
    if (savedFocus && byId(savedFocus.id)) {
      const input = byId(savedFocus.id); input.focus({preventScroll:true});
      if (typeof input.setSelectionRange === 'function' && savedFocus.start !== null) input.setSelectionRange(savedFocus.start,savedFocus.end);
    }
    savedFocus = null;
  }
  function filtersChanged() {
    selected.clear();
    [['filter-account','tl_acct'],['filter-status','tl_status'],['group-by','tl_groupby']].forEach(([id,key]) => write(key,byId(id).value));
    applyFilters();
  }
  function selectionChanged(checkbox) { checkbox.checked ? selected.add(checkbox.value) : selected.delete(checkbox.value); syncSelection(); }
  function clearSelection() { selected.clear(); syncSelection(); }
  function selectShown(checked) { eligibleRows().forEach(row => checked ? selected.add(row.dataset.taskId) : selected.delete(row.dataset.taskId)); syncSelection(); }
  function askDelete(ids) {
    if (!ids.length) return;
    pending = [...ids];
    const list = byId('delete-list'); list.replaceChildren();
    ids.forEach(id => {
      const row = rows().find(row => row.dataset.taskId === id);
      const item = document.createElement('li');
      item.textContent = row ? row.dataset.account + ' — ' + row.dataset.date : id; list.append(item);
    });
    byId('delete-title').textContent = 'Delete ' + ids.length + (ids.length === 1 ? ' report?' : ' reports?');
    byId('delete-confirm').textContent = 'Delete ' + ids.length + (ids.length === 1 ? ' report' : ' reports');
    byId('delete-error').hidden = true;
    byId('delete-dialog').showModal(); byId('delete-cancel').focus();
  }
  function deleteOne(id) { askDelete([id]); }
  function deleteSelected() { askDelete([...selected]); }
  function deleteShown() { askDelete(eligibleRows().map(row => row.dataset.taskId)); }
  function closeDelete() { if (!deleting) { byId('delete-dialog').close(); pending = []; } }
  function notify(message,error=false) {
    const el = byId('history-message'); el.textContent = message; el.classList.toggle('is-error',error); el.hidden = false;
  }
  async function confirmDelete() {
    if (deleting || !pending.length) return;
    deleting = true;
    byId('delete-confirm').disabled = true; byId('delete-cancel').disabled = true;
    byId('delete-confirm').textContent = 'Deleting…';
    try {
      const response = await fetch('/api/tasks/delete-selected', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({task_ids:pending})});
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'The reports could not be deleted. Please try again.');
      const failures = data.failed || [];
      const deleted = data.deleted_ids || [];
      deleted.forEach(id => selected.delete(id));
      byId('delete-dialog').close(); pending = [];
      notify(deleted.length + (deleted.length === 1 ? ' report deleted.' : ' reports deleted.') + (failures.length ? ' ' + failures.length + ' could not be deleted. ' + failures.map(f => f.error).filter((v,i,a) => a.indexOf(v) === i).join(' ') : ''),!!failures.length);
      await htmx.ajax('GET','/api/tasks/recent',{target:'#task-list',swap:'outerHTML'});
    } catch (error) {
      byId('delete-error').textContent = error.message || 'Deletion failed. Please try again.'; byId('delete-error').hidden = false;
    } finally {
      deleting = false; byId('delete-confirm').disabled = false; byId('delete-cancel').disabled = false;
      byId('delete-confirm').textContent = 'Delete reports';
    }
  }
  function renderAccounts(accounts) {
    const container = byId('results'); container.replaceChildren();
    if (byId('search-input').value.trim().length < 3) return;
    if (!accounts.length) { container.textContent = 'No accounts found. Try another name.'; return; }
    const count = document.createElement('p'); count.className='small text-muted mt-2 mb-0'; count.textContent = accounts.length + ' accounts found'; container.append(count);
    accounts.forEach(account => {
      const card = document.createElement('div'); card.className='account-result';
      const name = document.createElement('strong'); name.textContent = account.accountName;
      const key = document.createElement('div'); key.className='account-key font-monospace'; key.textContent = account.accountSwitchKey;
      const form = document.createElement('form'); form.method='post'; form.action='/api/reports'; form.className='account-actions';
      [['switch_key',account.accountSwitchKey],['account_name',account.accountName]].forEach(([name,value]) => {
        const input=document.createElement('input'); input.type='hidden'; input.name=name; input.value=value; form.append(input);
      });
      const select=document.createElement('select'); select.name='traffic_days'; select.className='form-select'; select.setAttribute('aria-label','Traffic window for ' + account.accountName);
      [15,30,90].forEach(days => { const option = document.createElement('option'); option.value=days; option.textContent=days+' days'; select.append(option); });
      const button=document.createElement('button'); button.type='submit'; button.className='btn btn-primary'; button.textContent='Run audit';
      form.append(select,button);
      form.addEventListener('submit',()=>{button.disabled=true;button.textContent='Starting…';});
      card.append(name,key,form); container.append(card);
    });
  }
  document.body.addEventListener('htmx:beforeRequest',event => {
    if (event.detail.elt.id === 'task-list' && byId('delete-dialog').open) event.preventDefault();
  });
  document.body.addEventListener('htmx:beforeSwap',event => {
    if (event.detail.target.id !== 'task-list') return;
    if (byId('delete-dialog').open) { event.preventDefault(); return; }
    const active = document.activeElement;
    if (active?.closest('#task-list') && active.id) savedFocus = {id:active.id,start:active.selectionStart ?? null,end:active.selectionEnd ?? null};
  });
  document.body.addEventListener('htmx:afterSwap',event => { if (event.detail.target.id === 'task-list') restore(); });
  document.body.addEventListener('htmx:afterRequest',event => {
    if (event.detail.elt.id !== 'search-input') return;
    if (!event.detail.successful) { byId('results').textContent='Account search failed. Please try again.'; return; }
    try { renderAccounts(JSON.parse(event.detail.xhr.responseText)); } catch { byId('results').textContent='Account search returned an unexpected response. Please try again.'; }
  });
  byId('delete-dialog').addEventListener('cancel',event=>{if(deleting)event.preventDefault();else pending=[];});
  return {filtersChanged,selectionChanged,clearSelection,selectShown,deleteOne,deleteSelected,deleteShown,closeDelete,confirmDelete};
})();
