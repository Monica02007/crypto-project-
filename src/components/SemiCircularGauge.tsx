interface SemiCircularGaugeProps {
  probability: number;
}

export function SemiCircularGauge({ probability }: SemiCircularGaugeProps) {
  const clamped = Math.max(0, Math.min(1, probability));
  const pct = Math.round(clamped * 100);

  const cx = 110;
  const cy = 100;
  const r = 74;
  const startAngle = Math.PI;
  const endAngle = 0;

  const arcPoint = (ratio: number, radius = r) => {
    const angle = startAngle + (endAngle - startAngle) * ratio;
    return {
      x: cx + radius * Math.cos(angle),
      y: cy - radius * Math.sin(angle),
    };
  };

  const segmentPath = (fromRatio: number, toRatio: number, radius = r) => {
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

  const ticks = [0, 0.25, 0.5, 0.75, 1];

  return (
    <div className="flex flex-col items-center py-1">
      <div className="w-52">
        <svg
          viewBox="0 0 220 122"
          className="w-full h-auto overflow-visible"
          role="img"
          aria-label={`Phishing probability gauge at ${pct}%`}
        >
          {/* Outer subtle track */}
          <path
            d={segmentPath(0, 1, r)}
            fill="none"
            stroke="#E2E8F0"
            strokeWidth="12"
            strokeLinecap="round"
          />

          {/* Semantic risk bands */}
          <path
            d={segmentPath(0, 0.39, r)}
            fill="none"
            stroke="#10B981"
            strokeOpacity="0.85"
            strokeWidth="12"
            strokeLinecap="round"
          />
          <path
            d={segmentPath(0.41, 0.71, r)}
            fill="none"
            stroke="#F59E0B"
            strokeOpacity="0.85"
            strokeWidth="12"
          />
          <path
            d={segmentPath(0.73, 1, r)}
            fill="none"
            stroke="#EF4444"
            strokeOpacity="0.9"
            strokeWidth="12"
            strokeLinecap="round"
          />

          {/* Inner hairline tick ring */}
          <path
            d={segmentPath(0, 1, r - 15)}
            fill="none"
            stroke="#CBD5E1"
            strokeWidth="1"
            strokeDasharray="2 4"
          />

          {ticks.map((t) => {
            const outer = arcPoint(t, r - 12);
            const inner = arcPoint(t, r - 18);
            return (
              <line
                key={t}
                x1={outer.x}
                y1={outer.y}
                x2={inner.x}
                y2={inner.y}
                stroke="#94A3B8"
                strokeWidth="1.5"
              />
            );
          })}

          {/* Needle */}
          <line
            x1={cx}
            y1={cy}
            x2={needleTip.x}
            y2={needleTip.y}
            stroke="#0F172A"
            strokeWidth="2.5"
            strokeLinecap="round"
          />
          <circle cx={cx} cy={cy} r="5.5" fill="#0F172A" />
          <circle cx={cx} cy={cy} r="2" fill="#FFFFFF" />

          {/* Score readout */}
          <text
            x={cx}
            y={cy - 20}
            textAnchor="middle"
            className="font-mono font-bold"
            fontSize="26"
            fill={statusColor}
          >
            {pct}%
          </text>

          {/* Scale labels */}
          <text x="20" y="116" textAnchor="middle" fontSize="9.5" fill="#64748B" className="font-mono">
            0%
          </text>
          <text x="110" y="14" textAnchor="middle" fontSize="9.5" fill="#64748B" className="font-mono">
            50%
          </text>
          <text x="200" y="116" textAnchor="middle" fontSize="9.5" fill="#64748B" className="font-mono">
            100%
          </text>
        </svg>
      </div>

      <div className="text-xs font-medium text-slate-600 -mt-1">
        ML Ensemble Score · <span style={{ color: statusColor }} className="font-semibold">{statusLabel}</span>
      </div>
    </div>
  );
}
