/**
 * Traffic dashboard charts + inline sparklines for report view.
 * Reads data from <script id="report-chart-data" type="application/json">.
 */
(function () {
  'use strict';

  const el = document.getElementById('report-chart-data');
  if (!el) return;

  let reportData;
  try { reportData = JSON.parse(el.textContent); } catch { return; }

  const properties = reportData.properties || [];
  if (!properties.length) return;

  // ---- aggregate per-property traffic ----
  const propTraffic = properties.map(p => {
    let edgeGB = 0, midGB = 0, originGB = 0, offloadSum = 0, offloadN = 0;
    (p.cpcodes || []).forEach(cp => {
      const t = cp.traffic || {};
      edgeGB += t.edgeBytes || 0;
      midGB += t.midgressBytes || 0;
      originGB += t.originBytes || 0;
      if (t.bytesOffload) { offloadSum += t.bytesOffload; offloadN++; }
    });
    return {
      name: p.name || p.id,
      edgeGB: Math.round(edgeGB * 100) / 100,
      midGB: Math.round(midGB * 100) / 100,
      originGB: Math.round(originGB * 100) / 100,
      offload: offloadN ? Math.round((offloadSum / offloadN) * 10) / 10 : 0,
      certDays: p.cert_expiry_days,
    };
  });

  // ---- color helpers ----
  function offloadColor(pct) {
    if (pct >= 90) return '#198754';  // green
    if (pct >= 70) return '#ffc107';  // yellow
    return '#dc3545';                 // red
  }
  function offloadColorAlpha(pct, a) {
    if (pct >= 90) return 'rgba(25,135,84,' + a + ')';
    if (pct >= 70) return 'rgba(255,193,7,' + a + ')';
    return 'rgba(220,53,69,' + a + ')';
  }

  // ---- Chart 1: Top 10 by Edge GB (horizontal bar) ----
  const top10 = [...propTraffic].sort((a, b) => b.edgeGB - a.edgeGB).slice(0, 10);

  const ctx1 = document.getElementById('chartTopEdge');
  if (ctx1 && top10.some(p => p.edgeGB > 0)) {
    new Chart(ctx1, {
      type: 'bar',
      data: {
        labels: top10.map(p => truncate(p.name, 25)),
        datasets: [{
          label: 'Edge GB',
          data: top10.map(p => p.edgeGB),
          backgroundColor: top10.map(p => offloadColorAlpha(p.offload, 0.8)),
          borderColor: top10.map(p => offloadColor(p.offload)),
          borderWidth: 1,
        }],
      },
      options: {
        indexAxis: 'y',
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          title: { display: true, text: 'Top 10 Properties by Edge GB', font: { size: 13 } },
          tooltip: {
            callbacks: {
              afterLabel: function (ctx) {
                const p = top10[ctx.dataIndex];
                return 'Offload: ' + p.offload + '% | Origin: ' + p.originGB + ' GB';
              },
            },
          },
        },
        scales: {
          x: { title: { display: true, text: 'GB' }, beginAtZero: true },
          y: { ticks: { font: { size: 11 } } },
        },
      },
    });
  } else if (ctx1) {
    showNoData(ctx1);
  }

  // ---- Chart 2: Offload Distribution (doughnut) ----
  const buckets = { high: 0, mid: 0, low: 0 };
  const propsWithTraffic = propTraffic.filter(p => p.edgeGB > 0);
  propsWithTraffic.forEach(p => {
    if (p.offload >= 90) buckets.high++;
    else if (p.offload >= 70) buckets.mid++;
    else buckets.low++;
  });

  const avgOffload = propsWithTraffic.length
    ? Math.round(propsWithTraffic.reduce((s, p) => s + p.offload, 0) / propsWithTraffic.length * 10) / 10
    : 0;

  const ctx2 = document.getElementById('chartOffloadDist');
  if (ctx2 && propsWithTraffic.length) {
    new Chart(ctx2, {
      type: 'doughnut',
      data: {
        labels: ['>90% (' + buckets.high + ')', '70-90% (' + buckets.mid + ')', '<70% (' + buckets.low + ')'],
        datasets: [{
          data: [buckets.high, buckets.mid, buckets.low],
          backgroundColor: ['#198754', '#ffc107', '#dc3545'],
          borderWidth: 2,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '60%',
        plugins: {
          title: { display: true, text: 'Offload Distribution', font: { size: 13 } },
          legend: { position: 'bottom', labels: { font: { size: 11 } } },
        },
      },
      plugins: [{
        id: 'centerText',
        afterDraw: function (chart) {
          const { ctx, chartArea } = chart;
          const cx = (chartArea.left + chartArea.right) / 2;
          const cy = (chartArea.top + chartArea.bottom) / 2;
          ctx.save();
          ctx.textAlign = 'center';
          ctx.textBaseline = 'middle';
          ctx.font = 'bold 22px sans-serif';
          ctx.fillStyle = offloadColor(avgOffload);
          ctx.fillText(avgOffload + '%', cx, cy - 6);
          ctx.font = '11px sans-serif';
          ctx.fillStyle = '#6c757d';
          ctx.fillText('avg offload', cx, cy + 14);
          ctx.restore();
        },
      }],
    });
  } else if (ctx2) {
    showNoData(ctx2);
  }

  // ---- Chart 3: Traffic Breakdown (stacked bar) ----
  const ctx3 = document.getElementById('chartTrafficBreak');
  if (ctx3 && top10.some(p => p.edgeGB > 0)) {
    new Chart(ctx3, {
      type: 'bar',
      data: {
        labels: top10.map(p => truncate(p.name, 25)),
        datasets: [
          { label: 'Edge GB', data: top10.map(p => p.edgeGB), backgroundColor: 'rgba(13,110,253,0.75)' },
          { label: 'Midgress GB', data: top10.map(p => p.midGB), backgroundColor: 'rgba(255,193,7,0.75)' },
          { label: 'Origin GB', data: top10.map(p => p.originGB), backgroundColor: 'rgba(220,53,69,0.75)' },
        ],
      },
      options: {
        indexAxis: 'y',
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          title: { display: true, text: 'Traffic Breakdown (Top 10)', font: { size: 13 } },
          legend: { position: 'bottom', labels: { font: { size: 11 } } },
        },
        scales: {
          x: { stacked: true, title: { display: true, text: 'GB' }, beginAtZero: true },
          y: { stacked: true, ticks: { font: { size: 11 } } },
        },
      },
    });
  } else if (ctx3) {
    showNoData(ctx3);
  }

  // ---- Cert expiry warnings ----
  const certWarnContainer = document.getElementById('certExpiryWarnings');
  if (certWarnContainer) {
    const expiring = propTraffic
      .filter(p => p.certDays !== null && p.certDays !== undefined)
      .filter(p => p.certDays <= 60)
      .sort((a, b) => (a.certDays || 999) - (b.certDays || 999));

    if (expiring.length) {
      let html = '';
      expiring.forEach(p => {
        const isRed = p.certDays <= 30;
        const cls = isRed ? 'danger' : 'warning';
        const icon = isRed ? 'exclamation-triangle-fill' : 'exclamation-circle-fill';
        html += '<span class="badge bg-' + cls + (isRed ? '' : ' text-dark') + ' me-2 mb-1">'
          + '<i class="bi bi-' + icon + ' me-1"></i>'
          + p.name + ' (' + p.certDays + 'd)'
          + '</span>';
      });
      certWarnContainer.innerHTML = '<div class="d-flex flex-wrap align-items-center gap-1">'
        + '<strong class="me-2"><i class="bi bi-shield-exclamation me-1"></i>Cert Warnings:</strong>'
        + html + '</div>';
      certWarnContainer.classList.remove('d-none');
    }
  }

  // ---- Inline sparklines ----
  document.querySelectorAll('canvas[data-sparkline-offload]').forEach(cvs => {
    const pct = parseFloat(cvs.dataset.sparklineOffload) || 0;
    const ctx = cvs.getContext('2d');
    const w = cvs.width, h = cvs.height;
    // background track
    ctx.fillStyle = '#e9ecef';
    ctx.fillRect(0, 0, w, h);
    // filled portion
    ctx.fillStyle = offloadColor(pct);
    ctx.fillRect(0, 0, w * (pct / 100), h);
    // percentage text
    if (w >= 60) {
      ctx.font = 'bold 9px sans-serif';
      ctx.fillStyle = pct > 50 ? '#fff' : '#333';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(pct + '%', w / 2, h / 2);
    }
  });

  // ---- helpers ----
  function truncate(s, n) { return s.length > n ? s.substring(0, n) + '...' : s; }

  function showNoData(canvas) {
    const parent = canvas.parentElement;
    parent.innerHTML = '<div class="d-flex align-items-center justify-content-center h-100 text-muted small">'
      + '<i class="bi bi-bar-chart me-2"></i>No traffic data available</div>';
  }
})();
