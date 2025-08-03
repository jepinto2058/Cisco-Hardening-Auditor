import { Severity } from '../constants.js';

export const calculateRiskLevel = (report) => {
    if (!report || !report.summary) return { text: 'Indeterminado', colorClass: 'bg-slate-600 text-slate-100', level: 0 };

    const { bySeverity } = report.summary;
    const criticals = bySeverity[Severity.CRITICAL] || 0;
    const highs = bySeverity[Severity.HIGH] || 0;
    const mediums = bySeverity[Severity.MEDIUM] || 0;

    if (criticals > 0) {
        return { text: 'Crítico', colorClass: 'bg-red-700 text-red-100', level: 4 };
    }
    if (highs > 0) {
        return { text: 'Alto', colorClass: 'bg-orange-600 text-orange-100', level: 3 };
    }
    if (mediums > 5) {
        return { text: 'Moderado', colorClass: 'bg-yellow-600 text-yellow-100', level: 2 };
    }
    return { text: 'Bajo', colorClass: 'bg-sky-600 text-sky-100', level: 1 };
};
