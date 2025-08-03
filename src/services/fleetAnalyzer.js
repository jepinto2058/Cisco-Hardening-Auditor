// This is a Web Worker, it runs in a separate thread.
import localforage from 'https://esm.sh/localforage@1.10.0';

import { analyzeConfiguration } from './analysisService.js';
import { calculateRiskLevel } from '../utils/risk.js';

self.onmessage = async (e) => {
    const { type, files } = e.data;

    if (type === 'start') {
        try {
            // It's good practice to clear storage for a new analysis run
            await localforage.clear();

            const allReports = [];
            const totalFiles = files.length;

            for (let i = 0; i < totalFiles; i++) {
                const file = files[i];
                const content = await file.text();
                const report = await analyzeConfiguration(file.name, content);
                
                allReports.push(report);

                // Store report in localforage for drill-down using the imported module
                await localforage.setItem(report.fileName, report);

                // Post progress back to the main thread
                self.postMessage({
                    type: 'progress',
                    payload: {
                        processed: i + 1,
                        total: totalFiles,
                        currentFile: file.name
                    }
                });
            }

            const fleetReport = aggregateReports(allReports);
            self.postMessage({ type: 'complete', payload: fleetReport });

        } catch (error) {
            console.error("Error in Fleet Analyzer worker:", error);
            self.postMessage({ type: 'error', payload: { message: `Worker error: ${error.message}` } });
        }
    }
};

function aggregateReports(reports) {
    const totalDevices = reports.length;
    if (totalDevices === 0) {
        return { kpis: {}, topCommonFindings: [], deviceReports: [] };
    }

    let totalScore = 0;
    let overallRiskLevel = { text: 'Bajo', colorClass: 'bg-sky-600 text-sky-100', level: 1 };
    let totalCriticals = 0;
    const commonFindings = new Map();
    const riskDistribution = { 'Crítico': 0, 'Alto': 0, 'Moderado': 0, 'Bajo': 0, 'Indeterminado': 0 };
    const scoreDistribution = { '0-49% (Débil)': 0, '50-74% (Aceptable)': 0, '75-89% (Sólida)': 0, '90-100% (Excelente)': 0 };
    const deviceReportSummaries = [];
    
    reports.forEach(report => {
        totalScore += report.summary.overallScore;
        totalCriticals += report.summary.bySeverity['Crítico'] || 0;

        const risk = calculateRiskLevel(report);
        if(risk.level > overallRiskLevel.level) {
            overallRiskLevel = risk;
        }
        riskDistribution[risk.text]++;

        const score = report.summary.overallScore;
        if (score < 50) scoreDistribution['0-49% (Débil)']++;
        else if (score < 75) scoreDistribution['50-74% (Aceptable)']++;
        else if (score < 90) scoreDistribution['75-89% (Sólida)']++;
        else scoreDistribution['90-100% (Excelente)']++;

        deviceReportSummaries.push({
            fileName: report.fileName,
            score: report.summary.overallScore,
            riskLevel: risk,
        });
        
        report.findings.forEach(finding => {
            if (finding.status === 'No Conforme') {
                const existing = commonFindings.get(finding.id);
                if (existing) {
                    existing.count++;
                } else {
                    commonFindings.set(finding.id, { count: 1, title: finding.title, severity: finding.severity });
                }
            }
        });
    });

    const topCommonFindings = [...commonFindings.entries()]
        .sort((a, b) => b[1].count - a[1].count)
        .slice(0, 5)
        .map(entry => ({ id: entry[0], ...entry[1] }));

    // Sort device summaries by risk, then score
    deviceReportSummaries.sort((a,b) => {
        if(b.riskLevel.level !== a.riskLevel.level) {
            return b.riskLevel.level - a.riskLevel.level;
        }
        return a.score - b.score;
    });

    return {
        kpis: {
            totalDevices,
            averageScore: Math.round(totalScore / totalDevices),
            overallRisk: overallRiskLevel,
            totalCriticals,
        },
        topCommonFindings,
        riskDistribution,
        scoreDistribution,
        deviceReports: deviceReportSummaries,
    };
}