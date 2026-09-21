function showColPicker(tabId, type) {
  const picker = document.getElementById(tabId + '-col-picker');
  if (!picker) return;
  picker.querySelector('.col-picker-cp').classList.toggle('d-none', type !== 'cp');
  picker.querySelector('.col-picker-hn').classList.toggle('d-none', type !== 'hn');
}

function toggleCol(tabId, type, colIdx, show) {
  const pane = document.getElementById(tabId + '-' + type);
  if (!pane) return;
  const table = pane.querySelector('table');
  if (!table) return;
  const ths = table.querySelectorAll('thead tr th');
  if (ths[colIdx]) ths[colIdx].style.display = show ? '' : 'none';
  table.querySelectorAll('tbody tr').forEach(function(row) {
    const tds = row.querySelectorAll('td');
    if (tds[colIdx]) tds[colIdx].style.display = show ? '' : 'none';
  });
}

function selectAllCols(tabId, type, show) {
  var picker = document.getElementById(tabId + '-col-picker');
  if (!picker) return;
  var section = picker.querySelector('.col-picker-' + type);
  if (!section) return;
  var checkboxes = section.querySelectorAll('input[type="checkbox"]');
  checkboxes.forEach(function(cb, idx) {
    cb.checked = show;
    toggleCol(tabId, type, idx, show);
  });
}

function onlyCol(tabId, type, colIdx) {
  var picker = document.getElementById(tabId + '-col-picker');
  if (!picker) return;
  var section = picker.querySelector('.col-picker-' + type);
  if (!section) return;
  var checkboxes = section.querySelectorAll('input[type="checkbox"]');
  checkboxes.forEach(function(cb, idx) {
    cb.checked = (idx === colIdx);
    toggleCol(tabId, type, idx, idx === colIdx);
  });
}

document.addEventListener('shown.bs.tab', function(e) {
  const btn = e.target;
  const target = btn.getAttribute('data-bs-target') || '';
  const match = target.match(/^#(prop-\d+-\d+)-(cp|hn)$/);
  if (match) showColPicker(match[1], match[2]);
});
