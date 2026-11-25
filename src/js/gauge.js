export function renderGaugeHtml(probability) {
  const clamped = Math.max(0, Math.min(1, probability));
  const pct = Math.round(clamped * 100);

  const cx = 110;
  const cy = 100;
  const r = 74;
  const startAngle = Math.PI;
  const endAngle = 0;

  const arcPoint = (ratio, radius = r) => {
    const angle = startAngle + (endAngle - startAngle) * ratio;
    return {
      x: cx + radius * Math.cos(angle),
      y: cy - radius * Math.sin(angle),
    };
  };

  const segmentPath = (fromRatio, toRatio, radius = r) => {
    const p1 = arcPoint(fromRatio, radius);
    const p2 = arcPoint(toRatio, radius);
    const largeArc = toRatio - fromRatio > 0.5 ? 1 : 0;
    return `M ${p1.x.toFixed(2)} ${p1.y.toFixed(2)} A ${radius} ${radius} 0 ${largeArc} 1 ${p2.x.toFixed(2)} ${p2.y.toFixed(2)}`;
  };

  const needleTip = arcPoint(clamped, r - 10);
  const statusColor =
    clamped >= 0.72 ? '#DC2626' : clamped >= 0.4 ? '#D97706' : '#059669';
  const statusLabel =
    clamped >= 0.72
      ? 'High Phishing Risk'
      : clamped >= 0.4
        ? 'Elevated Risk'
        : 'Low Risk Profile';

  const ticksHtml = [0, 0.25, 0.5, 0.75, 1]
    .map((t) => {
      const outer = arcPoint(t, r - 12);
      const inner = arcPoint(t, r - 18);
      return `<line x1="${outer.x.toFixed(2)}" y1="${outer.y.toFixed(2)}" x2="${inner.x.toFixed(2)}" y2="${inner.y.toFixed(2)}" stroke="#94A3B8" stroke-width="1.5" />`;
    })
    .join('');

  return `
    <div class="gauge-wrap">
      <div class="gauge-svg-box">
        <svg viewBox="0 0 220 122" class="gauge-svg" role="img" aria-label="Phishing probability gauge at ${pct}%">
          <path d="${segmentPath(0, 1, r)}" fill="none" stroke="#E2E8F0" stroke-width="12" stroke-linecap="round" />
          <path d="${segmentPath(0, 0.39, r)}" fill="none" stroke="#10B981" stroke-opacity="0.85" stroke-width="12" stroke-linecap="round" />
          <path d="${segmentPath(0.41, 0.71, r)}" fill="none" stroke="#F59E0B" stroke-opacity="0.85" stroke-width="12" />
          <path d="${segmentPath(0.73, 1, r)}" fill="none" stroke="#EF4444" stroke-opacity="0.9" stroke-width="12" stroke-linecap="round" />
          <path d="${segmentPath(0, 1, r - 15)}" fill="none" stroke="#CBD5E1" stroke-width="1" stroke-dasharray="2 4" />
          ${ticksHtml}
          <line x1="${cx}" y1="${cy}" x2="${needleTip.x.toFixed(2)}" y2="${needleTip.y.toFixed(2)}" stroke="#0F172A" stroke-width="2.5" stroke-linecap="round" />
          <circle cx="${cx}" cy="${cy}" r="5.5" fill="#0F172A" />
          <circle cx="${cx}" cy="${cy}" r="2" fill="#FFFFFF" />
          <text x="${cx}" y="${cy - 20}" text-anchor="middle" class="font-mono" font-weight="700" font-size="26" fill="${statusColor}">${pct}%</text>
          <text x="20" y="116" text-anchor="middle" font-size="9.5" fill="#64748B" class="font-mono">0%</text>
          <text x="110" y="14" text-anchor="middle" font-size="9.5" fill="#64748B" class="font-mono">50%</text>
          <text x="200" y="116" text-anchor="middle" font-size="9.5" fill="#64748B" class="font-mono">100%</text>
        </svg>
      </div>
      <div class="gauge-caption">
        ML Ensemble Score · <span style="color: ${statusColor}; font-weight: 600;">${statusLabel}</span>
      </div>
    </div>
  `;
}
