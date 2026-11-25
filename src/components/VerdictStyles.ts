import type { VerdictLevel } from '../core/types.ts';

export interface VerdictStyleSpec {
  containerClass: string;
  badgeTextClass: string;
  barClass: string;
  shortLabel: string;
}

export function getVerdictStyle(verdict: VerdictLevel): VerdictStyleSpec {
  switch (verdict) {
    case 'HIGH_RISK_KNOWN_THREAT':
    case 'HIGH_RISK_ML':
      return {
        containerClass: 'bg-red-50/70 border-red-200 text-slate-900',
        badgeTextClass: 'text-red-700',
        barClass: 'bg-red-600',
        shortLabel: 'High Risk',
      };
    case 'SUSPICIOUS':
      return {
        containerClass: 'bg-amber-50/70 border-amber-200 text-slate-900',
        badgeTextClass: 'text-amber-800',
        barClass: 'bg-amber-500',
        shortLabel: 'Suspicious',
      };
    case 'LOW_RISK':
      return {
        containerClass: 'bg-emerald-50/60 border-emerald-200 text-slate-900',
        badgeTextClass: 'text-emerald-700',
        barClass: 'bg-emerald-600',
        shortLabel: 'Low Risk',
      };
  }
}

export function formatPercent(prob: number): string {
  return `${(prob * 100).toFixed(1)}%`;
}
