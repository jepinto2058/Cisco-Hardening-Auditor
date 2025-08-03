


import { escapeHtml } from '../utils/escape.js';
import { Severity, FindingStatus } from '../constants.js';
import {
    createButtonHTML,
    createCardHTML,
    UploadCloudIcon,
    ChevronDownIcon,
    ChevronUpIcon,
    jsSeverityIcon,
    FileHtmlIcon,
    FilePdfIcon,
    CheckCircleIcon,
    ChartBarIcon,
    MagnifyingGlassIcon
} from './components.js';

// --- MAIN RENDER FUNCTION ---
export const renderApp = (state) => {
    const rootElement = document.getElementById('root');
    if (!rootElement) return;

    let mainContentHTML = '';
    switch (state.currentView) {
        case 'singleAnalysis':
            mainContentHTML = state.analysisReport ? renderAnalysisResultsDisplayHTML(state) : renderSingleAnalysisScreenHTML(state);
            break;
        case 'retestAnalysis':
            mainContentHTML = state.comparisonReport ? renderComparisonReportHTML(state) : renderRetestAnalysisScreenHTML(state);
            break;
        case 'fleetAnalysis':
             if (state.isLoadingFleet) {
                mainContentHTML = renderFleetAnalysisProgressHTML(state);
            } else if (state.fleetReport) {
                mainContentHTML = renderFleetReportHTML(state);
                if (state.selectedFleetDeviceReport) {
                    mainContentHTML += renderFleetDeviceDetailsHTML(state);
                }
            } else {
                mainContentHTML = renderFleetAnalysisScreenHTML(state);
            }
            break;
        case 'modeSelection':
        default:
            mainContentHTML = renderModeSelectionHTML();
            break;
    }

    rootElement.innerHTML = `
        <div class="min-h-screen flex flex-col bg-slate-900 text-slate-100">
            ${renderHeaderHTML(state.fleetReport)}
            <main class="flex-grow container mx-auto px-4 py-6 sm:py-8">
                ${mainContentHTML}
            </main>
            ${renderFooterHTML()}
            ${state.isSummaryModalOpen ? renderSummaryModalHTML(state) : ''}
            ${state.fleetComparisonReport ? renderFleetComparisonModalHTML(state) : ''}
        </div>
    `;
    
    if (state.currentView === 'singleAnalysis' && state.analysisReport && !state.comparisonReport) {
        updateFindingsList(state, 'findings-list-container');
    } else if (state.currentView === 'fleetAnalysis' && state.selectedFleetDeviceReport) {
        const subState = { ...state, analysisReport: state.selectedFleetDeviceReport };
        updateFindingsList(subState, 'findings-list-container-fleet-device');
    }
};

// --- HEADER AND FOOTER ---
const renderHeaderHTML = (fleetReportActive) => {
  const title = fleetReportActive ? "Dashboard de Salud de la Red" : "Auditor de Hardening Cisco";
  const tagline = fleetReportActive ? "Vista agregada de la postura de seguridad y riesgo tecnológico de todos sus dispositivos." : "Descubre vulnerabilidades y mejora la seguridad de tus routers y switches Cisco con nuestro análisis detallado.";
  return `
    <header class="bg-slate-800 shadow-lg sticky top-0 z-50">
      <div class="container mx-auto px-4 py-5 sm:py-6">
        <h1 class="text-2xl sm:text-3xl lg:text-4xl font-bold text-sky-400">${escapeHtml(title)}</h1>
        <p class="text-slate-300 mt-1 text-xs sm:text-sm lg:text-base">${escapeHtml(tagline)}</p>
      </div>
    </header>
  `;
};

const renderFooterHTML = () => {
  return `
    <footer class="bg-slate-800 py-6 mt-12 text-center text-slate-400 border-t border-slate-700">
      <div class="container mx-auto px-4">
        <p class="text-sm">&copy; ${new Date().getFullYear()} Analizador de Hardening Cisco. JP.</p>
        <p class="text-xs mt-1">Prueba siempre las configuraciones en un entorno de laboratorio antes de implementarlas en producción.</p>
      </div>
    </footer>
  `;
};

// --- APP VIEWS ---
const renderModeSelectionHTML = () => {
    const cardContent = `
        <h2 class="text-2xl font-semibold text-sky-400 text-center mb-6">Selecciona un Modo de Análisis</h2>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4 justify-center">
            <button id="select-single-analysis" class="bg-slate-700 hover:bg-slate-600 text-slate-100 p-6 rounded-lg w-full text-center transition-colors duration-200 focus:outline-none focus:ring-2 focus:ring-sky-500">
                <h3 class="text-xl font-bold mb-2 text-sky-300">Análisis Simple</h3>
                <p class="text-slate-300 text-sm">Sube un único archivo de configuración para analizar sus vulnerabilidades.</p>
            </button>
            <button id="select-retest-analysis" class="bg-slate-700 hover:bg-slate-600 text-slate-100 p-6 rounded-lg w-full text-center transition-colors duration-200 focus:outline-none focus:ring-2 focus:ring-sky-500">
                <h3 class="text-xl font-bold mb-2 text-sky-300">Análisis Comparativo</h3>
                <p class="text-slate-300 text-sm">Sube dos archivos (antes y después) para ver el progreso de la mitigación.</p>
            </button>
            <button id="select-fleet-analysis" class="bg-slate-700 hover:bg-slate-600 text-slate-100 p-6 rounded-lg w-full text-center transition-colors duration-200 focus:outline-none focus:ring-2 focus:ring-sky-500 border-2 border-sky-600">
                <h3 class="text-xl font-bold mb-2 text-sky-300">Análisis de Flota <span class="text-xs bg-sky-500/50 text-sky-200 px-2 py-0.5 rounded-full align-middle">Beta</span></h3>
                <p class="text-slate-300 text-sm">Sube múltiples archivos para obtener un dashboard de la salud de toda tu red.</p>
            </button>
        </div>
    `;
    return createCardHTML(null, cardContent, 'max-w-5xl mx-auto');
};

const renderSingleAnalysisScreenHTML = (state) => {
    let contentHTML = '';

    if (!state.uploadedFile) {
        contentHTML = renderFileUploadHTML(state, 'single');
    } else {
        contentHTML = `
            <div class="text-center space-y-4">
                <p class="text-lg">Archivo: <span class="font-semibold text-sky-300 break-all">${escapeHtml(state.uploadedFile?.name)}</span></p>
                <div class="flex flex-col sm:flex-row justify-center items-center space-y-3 sm:space-y-0 sm:space-x-4">
                    ${createButtonHTML('analyze-button', state.isLoading ? 'Analizando...' : 'Analizar Configuración', 'primary', 'w-full sm:w-auto', state.isLoading)}
                    ${createButtonHTML('clear-file-button', 'Quitar Archivo', 'secondary', 'w-full sm:w-auto', state.isLoading)}
                </div>
            </div>
        `;
    }

    if (state.isLoading) {
        contentHTML += `<div class="flex justify-center items-center space-x-2 mt-4" aria-label="Procesando análisis" role="status"><div class="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-sky-500"></div><p class="text-sky-400">Procesando, por favor espera...</p></div>`;
    }

    if (state.currentError && !state.isLoading) {
        contentHTML += `<div class="mt-4 p-3 bg-red-700/30 border border-red-500 rounded-md text-red-300 text-center" role="alert"><p><strong>Error:</strong> ${escapeHtml(state.currentError)}</p></div>`;
    }

    const cardContent = `
        <div class="p-6 space-y-6">
            <button id="back-to-mode-selection" class="text-sm text-sky-400 hover:text-sky-300 mb-4">&larr; Volver</button>
            <h2 class="text-2xl font-semibold text-sky-400 text-center">Analiza Tu Configuración</h2>
            ${contentHTML}
        </div>
    `;
    return createCardHTML(null, cardContent, 'max-w-2xl mx-auto');
};

const renderRetestAnalysisScreenHTML = (state) => {
    let contentHTML = `
        <div class="grid md:grid-cols-2 gap-8">
            <div>
                <h3 class="text-xl font-semibold text-center mb-4 text-slate-200">1. Archivo 'Antes' (Original)</h3>
                ${state.uploadedFileBefore ?
                    `<div class="text-center space-y-2 p-4 bg-slate-700/50 rounded-lg"><p class="text-md text-slate-300">Archivo: <span class="font-semibold text-sky-300 break-all">${escapeHtml(state.uploadedFileBefore.name)}</span></p><button id="clear-file-button-before" class="text-xs text-red-400 hover:text-red-300">Quitar</button></div>` :
                    renderFileUploadHTML(state, 'before')
                }
            </div>
            <div>
                <h3 class="text-xl font-semibold text-center mb-4 text-slate-200">2. Archivo 'Después' (Mitigado)</h3>
                ${state.uploadedFileAfter ?
                    `<div class="text-center space-y-2 p-4 bg-slate-700/50 rounded-lg"><p class="text-md text-slate-300">Archivo: <span class="font-semibold text-sky-300 break-all">${escapeHtml(state.uploadedFileAfter.name)}</span></p><button id="clear-file-button-after" class="text-xs text-red-400 hover:text-red-300">Quitar</button></div>` :
                    renderFileUploadHTML(state, 'after')
                }
            </div>
        </div>
        <div class="mt-8 flex justify-center">
            ${createButtonHTML('compare-button', state.isLoading ? 'Comparando...' : 'Comparar Configuraciones', 'primary', 'w-full md:w-auto', state.isLoading || !state.uploadedFileBefore || !state.uploadedFileAfter)}
        </div>
    `;

    if (state.isLoading) {
        contentHTML += `<div class="flex justify-center items-center space-x-2 mt-4" aria-label="Procesando comparación" role="status"><div class="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-sky-500"></div><p class="text-sky-400">Analizando ambos archivos...</p></div>`;
    }

    if (state.currentError && !state.isLoading) {
        contentHTML += `<div class="mt-4 p-3 bg-red-700/30 border border-red-500 rounded-md text-red-300 text-center" role="alert"><p><strong>Error:</strong> ${escapeHtml(state.currentError)}</p></div>`;
    }

    const cardContent = `
        <div class="p-6 space-y-6">
            <button id="back-to-mode-selection" class="text-sm text-sky-400 hover:text-sky-300 mb-4">&larr; Volver a la selección de modo</button>
            <h2 class="text-2xl font-semibold text-sky-400 text-center">Análisis Comparativo (Retest)</h2>
            <p class="text-center text-slate-300 max-w-2xl mx-auto">Sube la configuración original y la nueva configuración mitigada para ver qué vulnerabilidades se han solucionado y cuáles quedan pendientes.</p>
            ${contentHTML}
        </div>
    `;
    return createCardHTML(null, cardContent, 'max-w-4xl mx-auto');
};

const renderAnalysisResultsDisplayHTML = (state) => {
    if (!state.analysisReport) return '';
    const { analysisReport, isExportingPdf, filterSeverityState, filterComplianceState, sortOrderState } = state;
    const severityOrder = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFORMATIONAL];
    const severityCounts = analysisReport.summary.bySeverity;
    const statusCounts = analysisReport.summary.byStatus;

    const summaryContent = `
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 sm:gap-4 text-center">
            <div><p class="text-xs sm:text-sm text-slate-400">Nombre del Dispositivo</p><p class="text-sm sm:text-lg font-semibold text-sky-300 truncate" title="${escapeHtml(analysisReport.fileName)}">${escapeHtml(analysisReport.fileName)}</p></div>
            <div><p class="text-xs sm:text-sm text-slate-400">Fecha de Análisis</p><p class="text-sm sm:text-lg font-semibold text-sky-300">${new Date(analysisReport.analysisDate).toLocaleString('es-ES', {dateStyle:'medium', timeStyle:'short'})}</p></div>
            <div><p class="text-xs sm:text-sm text-slate-400">Verificaciones Totales</p><p class="text-sm sm:text-lg font-semibold text-sky-300">${analysisReport.summary.totalChecks}</p></div>
            <div><p class="text-xs sm:text-sm text-slate-400">Problemas Encontrados</p><p class="text-sm sm:text-lg font-semibold text-red-400">${analysisReport.summary.issuesFound}</p></div>
            ${analysisReport.summary.overallScore !== undefined ? `<div class="sm:col-span-2 lg:col-span-1"><p class="text-xs sm:text-sm text-slate-400">Puntuación General</p><p class="text-sm sm:text-lg font-semibold ${analysisReport.summary.overallScore >= 75 ? 'text-green-400' : analysisReport.summary.overallScore >= 50 ? 'text-yellow-400' : 'text-red-400'}">${analysisReport.summary.overallScore}%</p></div>` : ''}
        </div>
        <div class="mt-4 sm:mt-6">
            <h4 class="text-sm sm:text-md font-semibold text-slate-200 mb-2 text-center">Problemas por Severidad:</h4>
            <div class="flex flex-wrap justify-center gap-2 sm:gap-3">
                ${severityOrder.map(sev => (severityCounts[sev] ?? 0) > 0 ? `<div class="flex items-center space-x-2 p-2 bg-slate-700/70 rounded-md">${jsSeverityIcon(sev, "w-4 h-4 flex-shrink-0")}<span class="text-xs sm:text-sm text-slate-300">${escapeHtml(sev)}:</span><span class="text-xs sm:text-sm font-semibold text-sky-300">${severityCounts[sev] || 0}</span></div>` : '').join('')}
            </div>
        </div>
        <div class="mt-6 sm:mt-8 flex flex-col sm:flex-row flex-wrap justify-center items-center gap-3 sm:gap-4">
            ${createButtonHTML('summary-button', 'Resumen Ejecutivo', 'primary', 'w-full sm:w-auto', false, ChartBarIcon({className:"w-4 h-4 sm:w-5 sm:h-5"}))}
            ${createButtonHTML('export-html-button', `Exportar a HTML`, 'secondary', 'w-full sm:w-auto', false, FileHtmlIcon({className:"w-4 h-4 sm:w-5 sm:h-5"}))}
            ${createButtonHTML('export-pdf-button', `${isExportingPdf ? 'Exportando PDF...' : 'Exportar a PDF'}`, 'secondary', 'w-full sm:w-auto', isExportingPdf, FilePdfIcon({className:"w-4 h-4 sm:w-5 sm:h-5"}))}
        </div>
    `;

    const selectBaseClasses = "bg-slate-700 border border-slate-600 text-slate-100 text-sm rounded-md focus:ring-1 focus:ring-sky-500 focus:border-sky-500 p-2 w-full sm:w-auto";
    const findingsContent = `
        <div class="mb-4 flex flex-col sm:flex-row flex-wrap sm:items-center gap-4">
            <div class="flex-1 min-w-[150px]"><label for="severityFilter" class="block text-xs text-slate-300 mb-1">Filtrar por Severidad:</label><select id="severityFilter" class="${selectBaseClasses}"><option value="all" ${filterSeverityState === 'all' ? 'selected' : ''}>Todas (${analysisReport.findings.length})</option>${severityOrder.map(sev => `<option value="${escapeHtml(sev)}" ${filterSeverityState === sev ? 'selected' : ''}>${escapeHtml(sev)} (${severityCounts[sev] || 0})</option>`).join('')}</select></div>
            <div class="flex-1 min-w-[150px]"><label for="complianceFilter" class="block text-xs text-slate-300 mb-1">Filtrar por Cumplimiento:</label><select id="complianceFilter" class="${selectBaseClasses}"><option value="all" ${filterComplianceState === 'all' ? 'selected' : ''}>Todos</option><option value="${FindingStatus.COMPLIANT}" ${filterComplianceState === FindingStatus.COMPLIANT ? 'selected' : ''}>Conforme (${statusCounts[FindingStatus.COMPLIANT] || 0})</option><option value="${FindingStatus.NON_COMPLIANT}" ${filterComplianceState === FindingStatus.NON_COMPLIANT ? 'selected' : ''}>No Conforme (${statusCounts[FindingStatus.NON_COMPLIANT] || 0})</option></select></div>
            <div class="flex-1 min-w-[150px]"><label for="sortOrder" class="block text-xs text-slate-300 mb-1">Ordenar por:</label><select id="sortOrder" class="${selectBaseClasses}"><option value="severity" ${sortOrderState === 'severity' ? 'selected' : ''}>Severidad</option><option value="cis" ${sortOrderState === 'cis' ? 'selected' : ''}>Benchmark CIS</option><option value="status" ${sortOrderState === 'status' ? 'selected' : ''}>Estado</option></select></div>
        </div>
        <div id="findings-list-container"></div>
    `;

    return `<div><div class="mb-6 flex justify-end">${createButtonHTML('analyze-another-button', 'Analizar Otro Archivo', 'secondary', 'w-auto')}</div>${createCardHTML('Resumen del Análisis', summaryContent)}<div class="mt-6">${createCardHTML('Hallazgos Detallados', findingsContent)}</div></div>`;
};


const renderComparisonReportHTML = (state) => {
    if (!state.comparisonReport) return '';
    const { comparisonReport, isExportingPdf } = state;
    const { mitigatedCount, pendingCount, newCount, scoreBefore, scoreAfter, mitigatedFindings, pendingFindings, newFindings, fileNameBefore, fileNameAfter } = comparisonReport;

    mitigatedFindings.forEach(f => state.expandedFindings.add(f.id));

    const scoreChange = scoreAfter - scoreBefore;
    const scoreColor = scoreChange > 0 ? 'text-green-400' : scoreChange < 0 ? 'text-red-400' : 'text-slate-300';

    const summaryContent = `
        <div class="grid grid-cols-1 sm:grid-cols-3 gap-4 text-center mb-6">
            <div class="p-4 bg-slate-700/50 rounded-lg"><p class="text-2xl font-bold text-green-400">${mitigatedCount}</p><p class="text-sm text-slate-300">Hallazgos Mitigados</p></div>
            <div class="p-4 bg-slate-700/50 rounded-lg"><p class="text-2xl font-bold text-red-400">${pendingCount}</p><p class="text-sm text-slate-300">Hallazgos Pendientes</p></div>
            <div class="p-4 bg-slate-700/50 rounded-lg"><p class="text-2xl font-bold text-yellow-400">${newCount}</p><p class="text-sm text-slate-300">Hallazgos Nuevos</p></div>
        </div>
        <div class="grid grid-cols-2 gap-4 text-center">
             <div class="p-4 bg-slate-700/50 rounded-lg"><p class="text-xl font-bold text-sky-300">${scoreBefore}% &rarr; ${scoreAfter}%</p><p class="text-sm text-slate-300">Puntuación General</p></div>
            <div class="p-4 bg-slate-700/50 rounded-lg"><p class="text-xl font-bold ${scoreColor}">${scoreChange >= 0 ? '+' : ''}${scoreChange}%</p><p class="text-sm text-slate-300">Cambio en Puntuación</p></div>
        </div>
        <div class="mt-4 text-center text-xs text-slate-400">Comparando <span class="font-semibold">${escapeHtml(fileNameBefore)}</span> con <span class="font-semibold">${escapeHtml(fileNameAfter)}</span></div>
    `;

    const mitigatedContent = mitigatedFindings.length > 0 ? mitigatedFindings.map(f => renderFindingCardHTML(f, state, { isMitigated: true })).join('') : `<p class="text-slate-400 text-center py-4">No se mitigó ningún hallazgo.</p>`;
    const pendingContent = pendingFindings.length > 0 ? pendingFindings.map(f => renderFindingCardHTML(f, state)).join('') : `<p class="text-slate-400 text-center py-4">No quedan hallazgos pendientes.</p>`;
    const newContent = newFindings.length > 0 ? newFindings.map(f => renderFindingCardHTML(f, state)).join('') : `<p class="text-slate-400 text-center py-4">No se introdujeron nuevos hallazgos.</p>`;

    return `<div><div class="mb-6 flex flex-col sm:flex-row justify-end gap-3">${createButtonHTML('export-comparison-html-button', 'Exportar a HTML', 'secondary', 'w-full sm:w-auto', false, FileHtmlIcon({className:"w-4 h-4 sm:w-5 sm:h-5"}))}${createButtonHTML('export-comparison-pdf-button', isExportingPdf ? 'Exportando...' : 'Exportar a PDF', 'secondary', 'w-full sm:w-auto', isExportingPdf, FilePdfIcon({className:"w-4 h-4 sm:w-5 sm:h-5"}))}${createButtonHTML('analyze-another-button', 'Realizar Nuevo Análisis', 'secondary', 'w-full sm:w-auto')}</div>${createCardHTML('Resumen de la Comparación', summaryContent)}<div class="mt-8">${createCardHTML(`Hallazgos Mitigados (${mitigatedCount})`, mitigatedContent)}</div><div class="mt-8">${createCardHTML(`Hallazgos Pendientes (${pendingCount})`, pendingContent)}</div><div class="mt-8">${createCardHTML(`Hallazgos Nuevos (${newCount})`, newContent)}</div></div>`;
};

const renderFleetAnalysisScreenHTML = (state) => {
    const fileListHTML = state.fleetFiles.length > 0 ? `
        <div class="mt-6 space-y-2 max-h-60 overflow-y-auto custom-scrollbar pr-2">
            ${state.fleetFiles.map(file => `
                <div class="flex items-center justify-between bg-slate-700/50 p-2 rounded-md">
                    <span class="text-sm text-slate-300 truncate" title="${escapeHtml(file.name)}">${escapeHtml(file.name)}</span>
                    <button class="remove-fleet-file text-red-500 hover:text-red-400 p-1" data-filename="${escapeHtml(file.name)}">&times;</button>
                </div>
            `).join('')}
        </div>
    ` : '';
    
    let contentHTML = `
        ${renderFileUploadHTML(state, 'fleet')}
        ${fileListHTML}
        <div class="mt-8 flex justify-center">
            ${createButtonHTML('analyze-fleet-button', `Analizar ${state.fleetFiles.length} Archivo(s)`, 'primary', 'w-full md:w-auto', state.isLoadingFleet || state.fleetFiles.length === 0)}
        </div>
    `;

    if (state.currentError) {
        contentHTML += `<div class="mt-4 p-3 bg-red-700/30 border border-red-500 rounded-md text-red-300 text-center" role="alert"><p><strong>Error:</strong> ${escapeHtml(state.currentError)}</p></div>`;
    }

    const cardContent = `
        <div class="p-6 space-y-6">
            <button id="back-to-mode-selection" class="text-sm text-sky-400 hover:text-sky-300 mb-4">&larr; Volver a la selección de modo</button>
            <h2 class="text-2xl font-semibold text-sky-400 text-center">Análisis de Flota</h2>
            <p class="text-center text-slate-300 max-w-2xl mx-auto">Cargue múltiples archivos de configuración ('show running-config') para obtener una vista completa de la salud y riesgo de su red.</p>
            ${contentHTML}
        </div>
    `;
    return createCardHTML(null, cardContent, 'max-w-4xl mx-auto');
};


const renderFleetAnalysisProgressHTML = (state) => {
    const { processed, total, currentFile } = state.fleetAnalysisProgress;
    const progressPercentage = total > 0 ? Math.round((processed / total) * 100) : 0;
    return createCardHTML('Análisis de Flota en Progreso', `
        <div class="text-center p-8">
            <div class="animate-spin rounded-full h-12 w-12 border-t-4 border-b-4 border-sky-500 mx-auto"></div>
            <h3 class="text-xl font-semibold mt-6 text-slate-200">Analizando Dispositivos...</h3>
            <div class="w-full bg-slate-700 rounded-full h-2.5 mt-4">
                <div class="bg-sky-600 h-2.5 rounded-full" style="width: ${progressPercentage}%"></div>
            </div>
            <p class="mt-2 text-slate-400 text-sm">Progreso: ${processed} de ${total} (${progressPercentage}%)</p>
            <p class="mt-1 text-slate-300 text-sm truncate">Analizando: ${escapeHtml(currentFile)}</p>
        </div>
    `);
};

const renderFleetReportHTML = (state) => {
    const { fleetReport, fleetDevicesForComparison, isLoading } = state;
    if (!fleetReport) return '';

    const { kpis, topCommonFindings, deviceReports } = fleetReport;
    
    const kpisHTML = `
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-center">
            <div class="p-4 bg-slate-800/60 rounded-lg"><p class="text-xs text-slate-400">Total Dispositivos</p><p class="text-2xl font-bold text-sky-300">${kpis.totalDevices}</p></div>
            <div class="p-4 bg-slate-800/60 rounded-lg"><p class="text-xs text-slate-400">Puntuación Promedio</p><p class="text-2xl font-bold ${kpis.averageScore >= 75 ? 'text-green-400' : kpis.averageScore >= 50 ? 'text-yellow-400' : 'text-red-400'}">${kpis.averageScore}%</p></div>
            <div class="p-4 bg-slate-800/60 rounded-lg"><p class="text-xs text-slate-400">Nivel de Riesgo General</p><p class="text-2xl font-bold ${kpis.overallRisk.colorClass.replace('bg-','text-').replace('-100','-400')}">${kpis.overallRisk.text}</p></div>
            <div class="p-4 bg-slate-800/60 rounded-lg"><p class="text-xs text-slate-400">Hallazgos Críticos</p><p class="text-2xl font-bold text-red-400">${kpis.totalCriticals}</p></div>
        </div>
    `;

    const chartsHTML = `
        <div class="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6 mt-6">
            <div class="bg-slate-800/60 p-4 rounded-lg flex flex-col items-center justify-center min-h-[300px] xl:col-span-1">
                <h3 class="text-md font-semibold text-slate-200 mb-2">Top 5 Vulnerabilidades Comunes</h3>
                <ul class="w-full space-y-2 text-sm">
                    ${topCommonFindings.map(finding => `
                        <li class="flex justify-between items-center p-2 bg-slate-700/50 rounded-md">
                           <span class="truncate pr-2" title="${escapeHtml(finding.title)}">${escapeHtml(finding.title)}</span>
                           <span class="flex-shrink-0 font-bold bg-red-500/20 text-red-300 px-2 py-0.5 rounded-full text-xs">${finding.count}</span>
                        </li>
                    `).join('')}
                    ${topCommonFindings.length === 0 ? '<li class="text-center text-slate-400 py-4">¡No se encontraron vulnerabilidades comunes!</li>' : ''}
                </ul>
            </div>
             <div class="bg-slate-800/60 p-4 rounded-lg flex flex-col items-center justify-center min-h-[300px]">
                <h3 class="text-md font-semibold text-slate-200 mb-2">Distribución de Riesgo por Dispositivo</h3>
                <div class="relative w-full h-full min-h-[200px]" id="fleet-risk-chart-container"><canvas id="fleet-risk-chart"></canvas></div>
            </div>
            <div class="bg-slate-800/60 p-4 rounded-lg flex flex-col items-center justify-center min-h-[300px]">
                <h3 class="text-md font-semibold text-slate-200 mb-2">Distribución de Puntuaciones</h3>
                <div class="relative w-full h-full min-h-[200px]" id="fleet-score-chart-container"><canvas id="fleet-score-chart"></canvas></div>
            </div>
        </div>
    `;

    const compareButtonHTML = createButtonHTML(
        'compare-fleet-devices-button', 
        `Comparar (${fleetDevicesForComparison.size})`, 
        'primary', 
        '', 
        fleetDevicesForComparison.size !== 2 || isLoading, 
        `<svg class="w-5 h-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><title>Comparar</title><path stroke-linecap="round" stroke-linejoin="round" d="M19.5 12c0-1.232-.046-2.453-.138-3.662a4.006 4.006 0 00-3.7-3.7 48.678 48.678 0 00-7.324 0 4.006 4.006 0 00-3.7 3.7c-.092 1.21-.138 2.43-.138 3.662m14.862 0A48.49 48.49 0 0112 12.75c-2.733 0-5.281-.148-7.747-.423m15.494 0c.317.026.63.05.94.082m-1.923 2.825c.16.32.296.652.418.992a4.006 4.006 0 01-3.7 3.7 48.678 48.678 0 01-7.324 0 4.006 4.006 0 01-3.7-3.7c.122-.34.258-.672.418-.992m14.862 0c-.317-.026-.63-.05-.94-.082" /></svg>`
    );

    const tableHTML = `
        <div id="fleet-device-table-card" class="bg-slate-800/60 p-4 rounded-lg mt-6">
            <div class="flex flex-col sm:flex-row justify-between sm:items-center mb-4">
                <h3 class="text-lg font-semibold text-slate-200 mb-2 sm:mb-0">Lista de Dispositivos Analizados</h3>
                ${compareButtonHTML}
            </div>
            <div class="overflow-x-auto custom-scrollbar">
                <table class="w-full text-left text-sm">
                    <thead class="bg-slate-700/50 text-xs text-slate-300 uppercase">
                        <tr>
                            <th class="px-2 py-3 text-center w-12" title="Seleccionar para comparar">
                                <svg class="w-5 h-5 mx-auto" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><title>Comparar</title><path stroke-linecap="round" stroke-linejoin="round" d="M19.5 12c0-1.232-.046-2.453-.138-3.662a4.006 4.006 0 00-3.7-3.7 48.678 48.678 0 00-7.324 0 4.006 4.006 0 00-3.7 3.7c-.092 1.21-.138 2.43-.138 3.662m14.862 0A48.49 48.49 0 0112 12.75c-2.733 0-5.281-.148-7.747-.423m15.494 0c.317.026.63.05.94.082m-1.923 2.825c.16.32.296.652.418.992a4.006 4.006 0 01-3.7 3.7 48.678 48.678 0 01-7.324 0 4.006 4.006 0 01-3.7-3.7c.122-.34.258-.672.418-.992m14.862 0c-.317-.026-.63-.05-.94-.082" /></svg>
                            </th>
                            <th class="px-4 py-3">Dispositivo</th>
                            <th class="px-4 py-3 text-center">Puntuación</th>
                            <th class="px-4 py-3 text-center">Nivel de Riesgo</th>
                            <th class="px-4 py-3 text-center">Acciones</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-slate-700">
                    ${deviceReports.map(device => `
                        <tr class="hover:bg-slate-700/30 transition-colors duration-150 ${device.fileName === state.selectedFleetDeviceFileName ? 'bg-sky-900/60' : ''}" data-filename="${escapeHtml(device.fileName)}">
                            <td class="px-2 py-3 text-center">
                                <input 
                                    type="checkbox" 
                                    class="fleet-compare-checkbox h-4 w-4 rounded bg-slate-700 border-slate-500 text-sky-600 focus:ring-sky-500 disabled:opacity-50 disabled:cursor-not-allowed" 
                                    data-filename="${escapeHtml(device.fileName)}"
                                    ${fleetDevicesForComparison.has(device.fileName) ? 'checked' : ''}
                                    ${fleetDevicesForComparison.size >= 2 && !fleetDevicesForComparison.has(device.fileName) ? 'disabled' : ''}
                                    aria-label="Seleccionar ${escapeHtml(device.fileName)} para comparar"
                                >
                            </td>
                            <td class="px-4 py-3 font-medium text-sky-300">${escapeHtml(device.fileName)}</td>
                            <td class="px-4 py-3 text-center font-semibold ${device.score >= 75 ? 'text-green-400' : device.score >= 50 ? 'text-yellow-400' : 'text-red-400'}">${device.score}%</td>
                            <td class="px-4 py-3 text-center"><span class="px-2 py-1 rounded-full text-xs font-semibold ${device.riskLevel.colorClass}">${device.riskLevel.text}</span></td>
                            <td class="px-4 py-3 text-center">
                                <button class="view-fleet-device-details-button p-1.5 text-slate-400 hover:text-sky-400 rounded-full hover:bg-slate-700 transition-colors" data-filename="${escapeHtml(device.fileName)}" aria-label="Ver detalles de ${escapeHtml(device.fileName)}">
                                    ${MagnifyingGlassIcon({className: 'w-5 h-5'})}
                                </button>
                            </td>
                        </tr>
                    `).join('')}
                    </tbody>
                </table>
            </div>
        </div>
    `;
    
    return `
        <div>
            <div class="mb-6 flex justify-end">
                ${createButtonHTML('analyze-another-button', 'Realizar Nuevo Análisis de Flota', 'secondary', 'w-auto')}
            </div>
            ${createCardHTML('Indicadores Clave de Rendimiento (KPIs)', kpisHTML)}
            ${chartsHTML}
            ${tableHTML}
        </div>`;
};

// --- FILE UPLOAD AND FINDING CARD RENDERING ---
const renderFileUploadHTML = (state, targetId) => {
    const { dragActiveTarget, currentError, fileUploadSpecificErrorBefore, fileUploadSpecificErrorAfter } = state;
    const isDragActive = dragActiveTarget === targetId;
    const errorState = targetId === 'single' ? currentError : (targetId === 'before' ? fileUploadSpecificErrorBefore : fileUploadSpecificErrorAfter);
    const dragActiveClass = isDragActive ? 'border-sky-500 bg-slate-700/50' : 'border-slate-600 hover:border-slate-500 bg-slate-800 hover:bg-slate-700/30';
    const isMultiple = targetId === 'fleet';

    return `<div class="flex flex-col items-center justify-center w-full space-y-3"><label id="dropzone-label-${targetId}" for="dropzone-file-${targetId}" class="flex flex-col items-center justify-center w-full h-56 sm:h-64 border-2 border-dashed rounded-lg cursor-pointer ${dragActiveClass} transition-colors duration-200 ease-in-out" aria-describedby="file-upload-error-msg-${targetId}"><div class="flex flex-col items-center justify-center pt-5 pb-6 text-center">${UploadCloudIcon({ className: `w-10 h-10 sm:w-12 sm:h-12 mb-3 ${isDragActive ? 'text-sky-400' : 'text-slate-400'}` })}<p class="mb-2 text-sm sm:text-base ${isDragActive ? 'text-sky-300' : 'text-slate-300'}"><span class="font-semibold">Haz clic para subir</span> o arrastra y suelta</p><p class="text-xs sm:text-sm ${isDragActive ? 'text-sky-400' : 'text-slate-400'}">Archivos Cisco (.txt, .log, .cfg) - Máx 5MB</p></div><input id="dropzone-file-${targetId}" type="file" class="hidden" accept=".txt,.log,.cfg,text/plain" data-target="${targetId}" ${isMultiple ? 'multiple' : ''} /></label><p id="file-upload-error-msg-${targetId}" class="text-sm text-red-400 h-5" aria-live="polite">${errorState ? escapeHtml(errorState) : ''}</p></div>`;
};

const renderFindingCardHTML = (finding, state, options = {}) => {
    const { isMitigated = false } = options;
    const isExpanded = state.expandedFindings.has(finding.id);

    const getSeverityColorClasses = (severity) => {
        const colors = {
            [Severity.CRITICAL]: 'border-red-500 bg-red-900/10 hover:bg-red-800/20',
            [Severity.HIGH]: 'border-orange-500 bg-orange-900/10 hover:bg-orange-800/20',
            [Severity.MEDIUM]: 'border-yellow-500 bg-yellow-900/10 hover:bg-yellow-800/20',
            [Severity.LOW]: 'border-blue-500 bg-blue-900/10 hover:bg-blue-800/20',
            [Severity.INFORMATIONAL]: 'border-gray-600 bg-gray-800/10 hover:bg-gray-700/20'
        };
        return colors[severity] || 'border-slate-700 bg-slate-800/10 hover:bg-slate-700/20';
    };

    const getStatusClasses = (status, isMitigatedFlag) => {
        if (isMitigatedFlag) return 'bg-green-700/40 text-green-200';
        const classes = {
            [FindingStatus.COMPLIANT]: 'bg-green-800/40 text-green-300',
            [FindingStatus.NON_COMPLIANT]: 'bg-red-700/30 text-red-300',
            [FindingStatus.NOT_APPLICABLE]: 'bg-slate-600/50 text-slate-300',
            [FindingStatus.ERROR]: 'bg-yellow-700/30 text-yellow-300'
        };
        return classes[status] || 'bg-slate-700 text-slate-200';
    };

    const cardClasses = isMitigated ? 'border-green-500 bg-green-900/20 hover:bg-green-800/30' : getSeverityColorClasses(finding.severity);
    const statusClasses = getStatusClasses(finding.status, isMitigated);
    const statusText = isMitigated ? `Mitigado (${escapeHtml(finding.severity)})` : escapeHtml(finding.status);

    const cardHeaderHTML = `<div class="flex items-center justify-between"><div class="flex items-center space-x-2 sm:space-x-3 min-w-0">${isMitigated ? CheckCircleIcon({className: 'w-5 h-5 text-green-400 flex-shrink-0'}) : jsSeverityIcon(finding.severity, 'w-4 h-4 sm:w-5 sm:h-5 flex-shrink-0')}<h3 class="text-md sm:text-lg font-semibold ${isMitigated ? 'text-green-300' : 'text-sky-300'} truncate" title="${escapeHtml(finding.title)}">${escapeHtml(finding.title)}</h3></div><div class="flex items-center space-x-2 sm:space-x-3 flex-shrink-0"><span class="text-xs sm:text-sm font-medium px-2 py-0.5 rounded-full ${statusClasses}">${statusText}</span>${isExpanded ? ChevronUpIcon({className: "w-5 h-5 text-slate-400"}) : ChevronDownIcon({className: "w-5 h-5 text-slate-400"})}</div></div><p class="text-xs text-slate-400 mt-1 truncate" title="${escapeHtml(finding.cisBenchmark)}">${escapeHtml(finding.cisBenchmark)}</p>`;

    let cardBodyHTML = '';
    if (isExpanded) {
        cardBodyHTML = `<div class="px-4 pb-4 pt-3 border-t ${isMitigated ? 'border-green-700/50' : 'border-slate-700/50'} space-y-3 mt-3"><div><h4 class="font-semibold text-slate-200 mb-1 text-sm">Descripción:</h4><p class="text-sm text-slate-300">${escapeHtml(finding.description)}</p></div>${finding.geminiExplanation ? `<div><h4 class="font-semibold text-slate-200 mb-1 text-sm">Explicación Mejorada:</h4><p class="text-sm text-slate-300 italic bg-slate-700/30 p-2 rounded">${escapeHtml(finding.geminiExplanation)}</p></div>` : ''}${finding.affectedLines && finding.affectedLines.length > 0 ? `<div><h4 class="font-semibold text-slate-200 mb-1 text-sm">Configuración Afectada:</h4><pre class="text-xs bg-slate-950 p-2 rounded-md overflow-x-auto custom-scrollbar"><code>${escapeHtml(finding.affectedLines.join('\n'))}</code></pre></div>` : ''}<div><h4 class="font-semibold text-slate-200 mb-1 text-sm">Recomendación:</h4><p class="text-sm text-slate-300 whitespace-pre-line">${escapeHtml(finding.recommendation)}</p></div></div>`;
    }

    return `<div class="bg-slate-800/70 shadow-lg rounded-md mb-4 ${cardClasses} border-l-4 transition-all duration-200 ease-in-out" data-finding-id="${escapeHtml(finding.id)}"><div class="p-3 sm:p-4 clickable finding-header" role="button" tabindex="0" aria-expanded="${isExpanded}" aria-controls="finding-details-${escapeHtml(finding.id)}">${cardHeaderHTML}</div><div id="finding-details-${escapeHtml(finding.id)}" class="finding-details-content ${isExpanded ? 'block' : 'hidden'}">${cardBodyHTML}</div></div>`;
};


// --- DYNAMIC CONTENT UPDATE ---
export const updateFindingsList = (state, containerId) => {
    if (!state.analysisReport) return;

    let processedFindings = [...state.analysisReport.findings];

    if (state.filterSeverityState !== 'all') {
        processedFindings = processedFindings.filter(f => f.severity === state.filterSeverityState);
    }
    if (state.filterComplianceState !== 'all') {
        processedFindings = processedFindings.filter(f => f.status === state.filterComplianceState);
    }

    const severityOrder = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFORMATIONAL];
    switch(state.sortOrderState) {
        case 'severity':
            processedFindings.sort((a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity));
            break;
        case 'cis':
            processedFindings.sort((a, b) => a.cisBenchmark.localeCompare(b.cisBenchmark));
            break;
        case 'status':
            processedFindings.sort((a, b) => a.status.localeCompare(b.status));
            break;
    }

    const findingsListContainer = document.getElementById(containerId);
    if (findingsListContainer) {
        findingsListContainer.innerHTML = processedFindings.length > 0
            ? processedFindings.map(finding => renderFindingCardHTML(finding, state)).join('')
            : `<p class="text-slate-400 text-center py-4">No se encontraron hallazgos que coincidan con los filtros.</p>`;
    }
};

const renderSummaryModalHTML = (state) => {
    const reportForModal = state.selectedFleetDeviceReport || state.analysisReport;
    if (!reportForModal) return '';

    const riskLevel = state.riskLevel;

    const riskCardHTML = `
      <div class="bg-slate-900/50 p-4 rounded-lg flex flex-col items-center justify-center min-h-[250px]">
        <h3 class="text-md font-semibold text-slate-200 mb-4">Nivel de Riesgo Evaluado</h3>
        <div class="flex items-center justify-center w-32 h-32 sm:w-40 sm:h-40 rounded-full ${riskLevel.colorClass} shadow-lg transition-all">
          <span class="text-xl sm:text-2xl font-bold">${escapeHtml(riskLevel.text)}</span>
        </div>
      </div>
    `;

    return `
    <div id="summary-modal-overlay" class="fixed inset-0 bg-black/70 z-[100] flex items-center justify-center p-4" role="dialog" aria-modal="true" aria-labelledby="summary-modal-title">
      <style>
        @keyframes fade-in { 0% { opacity: 0; } 100% { opacity: 1; } }
        @keyframes slide-up { 0% { opacity: 0; transform: translateY(20px); } 100% { opacity: 1; transform: translateY(0); } }
        .animate-fade-in { animation: fade-in 0.3s ease-out forwards; }
        .animate-slide-up { animation: slide-up 0.4s ease-out forwards; }
      </style>
      <div class="bg-slate-800 rounded-xl shadow-2xl w-full max-w-4xl max-h-[90vh] flex flex-col animate-fade-in">
        <div class="animate-slide-up" style="animation-delay: 0.1s; display: contents;">
          <header class="flex items-center justify-between p-4 border-b border-slate-700 flex-shrink-0">
            <h2 id="summary-modal-title" class="text-xl font-bold text-sky-400">Resumen Ejecutivo del Análisis</h2>
            <button id="close-summary-modal-button" class="text-slate-400 hover:text-white" aria-label="Cerrar modal">
              <svg class="w-6 h-6" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
            </button>
          </header>
          <div class="p-6 overflow-y-auto custom-scrollbar">
            <div class="mb-6 p-4 bg-slate-900/50 rounded-lg">
                <h3 class="font-semibold text-slate-200 mb-2">Evaluación General:</h3>
                <p class="text-slate-300 text-sm">${escapeHtml(state.executiveSummary)}</p>
            </div>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
              ${riskCardHTML}
              <div class="bg-slate-900/50 p-4 rounded-lg flex flex-col items-center justify-center min-h-[250px]">
                <h3 class="text-md font-semibold text-slate-200 mb-2">Puntuación General</h3>
                <div class="relative w-full h-full min-h-[180px]"><canvas id="summary-gauge-chart"></canvas></div>
              </div>
              <div class="bg-slate-900/50 p-4 rounded-lg flex flex-col items-center justify-center min-h-[250px]">
                <h3 class="text-md font-semibold text-slate-200 mb-2">Problemas por Severidad</h3>
                <div class="relative w-full h-full min-h-[180px]"><canvas id="summary-severity-chart"></canvas></div>
              </div>
              <div class="bg-slate-900/50 p-4 rounded-lg flex flex-col items-center justify-center min-h-[250px]">
                <h3 class="text-md font-semibold text-slate-200 mb-2">Estado de Verificaciones</h3>
                 <div class="relative w-full h-full min-h-[180px]"><canvas id="summary-status-chart"></canvas></div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  `;
}

export const initializeSummaryCharts = (state) => {
    const reportToChart = state.selectedFleetDeviceReport || state.analysisReport;
    if (!reportToChart) return;
    const { summary } = reportToChart;

    const ctxGauge = document.getElementById('summary-gauge-chart');
    const ctxSeverity = document.getElementById('summary-severity-chart');
    const ctxStatus = document.getElementById('summary-status-chart');

    const score = summary.overallScore;
    const scoreColor = score >= 90 ? '#4ade80' : score >= 75 ? '#38bdf8' : score >= 50 ? '#facc15' : '#f87171';
    
    if (window.summaryCharts) {
        Object.values(window.summaryCharts).forEach(chart => { if(chart) chart.destroy(); });
    }
    window.summaryCharts = {};

    if (ctxGauge) {
        window.summaryCharts.gauge = new Chart(ctxGauge, {
            type: 'doughnut',
            data: {
                datasets: [{
                    data: [score, 100 - score],
                    backgroundColor: [scoreColor, '#334155'],
                    borderColor: ['#1e293b'],
                    borderWidth: 2,
                    circumference: 180,
                    rotation: 270,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '70%',
                plugins: {
                    legend: { display: false },
                    tooltip: { enabled: false },
                },
                animation: {
                    animateRotate: true,
                    animateScale: true,
                }
            },
            plugins: [{
                id: 'gaugeText',
                afterDraw: chart => {
                    const ctx = chart.ctx;
                    const { width, height } = chart;
                    ctx.restore();
                    const fontSize = (height / 114).toFixed(2);
                    ctx.font = `bold ${fontSize}em sans-serif`;
                    ctx.textBaseline = "middle";
                    ctx.fillStyle = scoreColor;
                    const text = `${score}%`;
                    const textX = Math.round((width - ctx.measureText(text).width) / 2);
                    const textY = height / 1.5;
                    ctx.fillText(text, textX, textY);
                    ctx.save();
                }
            }]
        });
    }

    if (ctxSeverity) {
        const severityOrder = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFORMATIONAL];
        const severityColors = {
            [Severity.CRITICAL]: '#ef4444', [Severity.HIGH]: '#f97316', [Severity.MEDIUM]: '#eab308',
            [Severity.LOW]: '#3b82f6', [Severity.INFORMATIONAL]: '#6b7280'
        };
        const labels = severityOrder.filter(s => summary.bySeverity[s] > 0);
        const data = labels.map(s => summary.bySeverity[s]);
        const colors = labels.map(s => severityColors[s]);

        window.summaryCharts.severity = new Chart(ctxSeverity, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Problemas',
                    data: data,
                    backgroundColor: colors,
                    borderColor: colors,
                    borderWidth: 1
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: {
                       grid: { color: '#334155' },
                       ticks: { color: '#94a3b8', beginAtZero: true, precision: 0 }
                    },
                    y: {
                       grid: { display: false },
                       ticks: { color: '#94a3b8' }
                    }
                },
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        backgroundColor: '#1e293b',
                        titleColor: '#e2e8f0',
                        bodyColor: '#cbd5e1',
                    }
                }
            }
        });
    }

    if (ctxStatus) {
        const compliant = summary.byStatus[FindingStatus.COMPLIANT] || 0;
        const nonCompliant = summary.byStatus[FindingStatus.NON_COMPLIANT] || 0;
        window.summaryCharts.status = new Chart(ctxStatus, {
            type: 'doughnut',
            data: {
                labels: ['Conforme', 'No Conforme'],
                datasets: [{
                    data: [compliant, nonCompliant],
                    backgroundColor: ['#22c55e', '#ef4444'],
                    borderColor: '#334155',
                    borderWidth: 3,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'top', labels: { color: '#94a3b8', font: {size: 14} } },
                    tooltip: {
                         backgroundColor: '#1e293b',
                         titleColor: '#e2e8f0',
                         bodyColor: '#cbd5e1',
                    }
                }
            }
        });
    }
}


export const initializeFleetCharts = (fleetReport) => {
    if (!fleetReport) return;

    const ctxRisk = document.getElementById('fleet-risk-chart');
    const ctxScore = document.getElementById('fleet-score-chart');
    const riskContainer = document.getElementById('fleet-risk-chart-container');
    const scoreContainer = document.getElementById('fleet-score-chart-container');

    if (window.fleetCharts) {
        Object.values(window.fleetCharts).forEach(chart => { if (chart) chart.destroy(); });
    }
    window.fleetCharts = {};

    if (ctxRisk && riskContainer) {
        const riskData = fleetReport.riskDistribution;
        const filteredRiskData = Object.entries(riskData).filter(([, count]) => count > 0);

        if (filteredRiskData.length === 0) {
            riskContainer.innerHTML = `<div class="flex items-center justify-center h-full text-slate-400">No hay datos de riesgo para mostrar.</div>`;
        } else {
            const labels = filteredRiskData.map(([label,]) => label);
            const data = filteredRiskData.map(([, count]) => count);
            const colors = labels.map(label => {
                switch (label) {
                    case 'Crítico': return '#ef4444';
                    case 'Alto': return '#f97316';
                    case 'Moderado': return '#eab308';
                    case 'Bajo': return '#3b82f6';
                    case 'Indeterminado': return '#64748b';
                    default: return '#6b7280';
                }
            });

            window.fleetCharts.risk = new Chart(ctxRisk, {
                type: 'doughnut',
                data: {
                    labels: labels,
                    datasets: [{
                        label: 'Dispositivos',
                        data: data,
                        backgroundColor: colors,
                        borderColor: '#334155',
                        borderWidth: 4,
                        hoverBorderWidth: 6,
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    cutout: '60%',
                    plugins: {
                        legend: { position: 'top', labels: { color: '#94a3b8', boxWidth: 15, padding: 20 } },
                        tooltip: {
                            backgroundColor: '#1e293b',
                            titleColor: '#e2e8f0',
                            bodyColor: '#cbd5e1',
                            callbacks: {
                                label: function(context) {
                                    const total = context.chart.data.datasets[0].data.reduce((a, b) => a + b, 0);
                                    const percentage = total > 0 ? (context.parsed / total * 100).toFixed(1) : 0;
                                    return ` ${context.label}: ${context.raw} Dispositivos (${percentage}%)`;
                                }
                            }
                        }
                    }
                },
                plugins: [{
                    id: 'doughnutCenterText',
                    afterDraw: chart => {
                        const { ctx, width, height } = chart;
                        const totalDevices = chart.data.datasets[0].data.reduce((a, b) => a + b, 0);
                        ctx.restore();
                        
                        const subText = "Dispositivos";
                        const subFontSize = (height / 200).toFixed(2);
                        ctx.font = `${subFontSize}em sans-serif`;
                        ctx.fillStyle = '#64748b';
                        ctx.textBaseline = "alphabetic";
                        const subTextX = Math.round((width - ctx.measureText(subText).width) / 2);
                        const subTextY = height / 2 - 5;
                        ctx.fillText(subText, subTextX, subTextY);
                        
                        const text = `${totalDevices}`;
                        const fontSize = (height / 110).toFixed(2);
                        ctx.font = `bold ${fontSize}em sans-serif`;
                        ctx.fillStyle = '#e2e8f0';
                        ctx.textBaseline = "hanging";
                        const textX = Math.round((width - ctx.measureText(text).width) / 2);
                        const textY = height / 2 - 5;
                        ctx.fillText(text, textX, textY);

                        ctx.save();
                    }
                }]
            });
        }
    }

    if (ctxScore && scoreContainer) {
        const scoreData = fleetReport.scoreDistribution;
        const labels = Object.keys(scoreData);
        const data = Object.values(scoreData);
        const totalDevicesInScoreChart = data.reduce((a, b) => a + b, 0);
        
        if (totalDevicesInScoreChart === 0) {
             scoreContainer.innerHTML = `<div class="flex items-center justify-center h-full text-slate-400">No hay datos de puntuación para mostrar.</div>`;
        } else {
            window.fleetCharts.score = new Chart(ctxScore, {
                type: 'bar',
                data: {
                    labels: labels,
                    datasets: [{
                        label: 'Número de Dispositivos',
                        data: data,
                        backgroundColor: (context) => {
                            const chart = context.chart;
                            const { ctx, chartArea } = chart;
                            if (!chartArea) { return null; }
                            
                            const gradientColors = [
                                ['#ef4444', '#f87171'], // 0-49%
                                ['#eab308', '#facc15'], // 50-74%
                                ['#3b82f6', '#60a5fa'], // 75-89%
                                ['#22c55e', '#4ade80']  // 90-100%
                            ];
                            const index = context.dataIndex % gradientColors.length;
                            const colors = gradientColors[index];
                            
                            const gradient = ctx.createLinearGradient(chartArea.left, 0, chartArea.right, 0);
                            gradient.addColorStop(0, colors[0]);
                            gradient.addColorStop(1, colors[1]);
                            return gradient;
                        },
                        borderRadius: 4,
                        borderSkipped: false,
                    }]
                },
                options: {
                    indexAxis: 'y',
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        x: { 
                            grid: { color: '#334155' }, 
                            ticks: { color: '#94a3b8', precision: 0 },
                            min: 0
                        },
                        y: { 
                            grid: { display: false }, 
                            ticks: { color: '#94a3b8' } 
                        }
                    },
                    plugins: {
                        legend: { display: false },
                        tooltip: { backgroundColor: '#1e293b' }
                    }
                },
                plugins: [{
                    id: 'barDataLabels',
                    afterDatasetsDraw: (chart) => {
                        const { ctx, data, scales: { x, y } } = chart;
                        ctx.save();
                        
                        data.datasets[0].data.forEach((datapoint, index) => {
                            if (datapoint === 0) return;
                            
                            const yPos = y.getPixelForValue(index);
                            const xPos = x.getPixelForValue(datapoint);
                            
                            ctx.font = 'bold 12px sans-serif';
                            ctx.textBaseline = 'middle';
                            
                            let textX = xPos - 5;
                            ctx.textAlign = 'right';
                            ctx.fillStyle = 'rgba(255, 255, 255, 0.9)';

                            if (x.getPixelForValue(datapoint) < x.left + 30) {
                                textX = xPos + 5;
                                ctx.textAlign = 'left';
                                ctx.fillStyle = '#e2e8f0';
                            }
                            
                            ctx.fillText(datapoint, textX, yPos);
                        });
                        
                        ctx.restore();
                    }
                }]
            });
        }
    }
};

const renderFleetDeviceDetailsHTML = (state) => {
    if (!state.selectedFleetDeviceReport) return '';
    const { selectedFleetDeviceReport: analysisReport, isExportingPdf, filterSeverityState, filterComplianceState, sortOrderState } = state;
    const severityOrder = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFORMATIONAL];
    const severityCounts = analysisReport.summary.bySeverity;
    const statusCounts = analysisReport.summary.byStatus;

    const summaryContent = `
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 sm:gap-4 text-center">
            <div><p class="text-xs sm:text-sm text-slate-400">Nombre del Dispositivo</p><p class="text-sm sm:text-lg font-semibold text-sky-300 truncate" title="${escapeHtml(analysisReport.fileName)}">${escapeHtml(analysisReport.fileName)}</p></div>
            <div><p class="text-xs sm:text-sm text-slate-400">Fecha de Análisis</p><p class="text-sm sm:text-lg font-semibold text-sky-300">${new Date(analysisReport.analysisDate).toLocaleString('es-ES', {dateStyle:'medium', timeStyle:'short'})}</p></div>
            <div><p class="text-xs sm:text-sm text-slate-400">Verificaciones Totales</p><p class="text-sm sm:text-lg font-semibold text-sky-300">${analysisReport.summary.totalChecks}</p></div>
            <div><p class="text-xs sm:text-sm text-slate-400">Problemas Encontrados</p><p class="text-sm sm:text-lg font-semibold text-red-400">${analysisReport.summary.issuesFound}</p></div>
            ${analysisReport.summary.overallScore !== undefined ? `<div class="sm:col-span-2 lg:col-span-1"><p class="text-xs sm:text-sm text-slate-400">Puntuación General</p><p class="text-sm sm:text-lg font-semibold ${analysisReport.summary.overallScore >= 75 ? 'text-green-400' : analysisReport.summary.overallScore >= 50 ? 'text-yellow-400' : 'text-red-400'}">${analysisReport.summary.overallScore}%</p></div>` : ''}
        </div>
        <div class="mt-4 sm:mt-6">
            <h4 class="text-sm sm:text-md font-semibold text-slate-200 mb-2 text-center">Problemas por Severidad:</h4>
            <div class="flex flex-wrap justify-center gap-2 sm:gap-3">
                ${severityOrder.map(sev => (severityCounts[sev] ?? 0) > 0 ? `<div class="flex items-center space-x-2 p-2 bg-slate-700/70 rounded-md">${jsSeverityIcon(sev, "w-4 h-4 flex-shrink-0")}<span class="text-xs sm:text-sm text-slate-300">${escapeHtml(sev)}:</span><span class="text-xs sm:text-sm font-semibold text-sky-300">${severityCounts[sev] || 0}</span></div>` : '').join('')}
            </div>
        </div>
        <div class="mt-6 sm:mt-8 flex flex-col sm:flex-row flex-wrap justify-center items-center gap-3 sm:gap-4">
            ${createButtonHTML('summary-button', 'Resumen Ejecutivo', 'primary', 'w-full sm:w-auto', false, ChartBarIcon({className:"w-4 h-4 sm:w-5 sm:h-5"}))}
            ${createButtonHTML('close-fleet-device-details-button', 'Cerrar Detalles', 'secondary', 'w-full sm:w-auto')}
        </div>
    `;

    const selectBaseClasses = "bg-slate-700 border border-slate-600 text-slate-100 text-sm rounded-md focus:ring-1 focus:ring-sky-500 focus:border-sky-500 p-2 w-full sm:w-auto";
    const findingsContent = `
        <div class="mb-4 flex flex-col sm:flex-row flex-wrap sm:items-center gap-4">
            <div class="flex-1 min-w-[150px]"><label for="severityFilter" class="block text-xs text-slate-300 mb-1">Filtrar por Severidad:</label><select id="severityFilter" class="${selectBaseClasses}"><option value="all" ${filterSeverityState === 'all' ? 'selected' : ''}>Todas (${analysisReport.findings.length})</option>${severityOrder.map(sev => `<option value="${escapeHtml(sev)}" ${filterSeverityState === sev ? 'selected' : ''}>${escapeHtml(sev)} (${severityCounts[sev] || 0})</option>`).join('')}</select></div>
            <div class="flex-1 min-w-[150px]"><label for="complianceFilter" class="block text-xs text-slate-300 mb-1">Filtrar por Cumplimiento:</label><select id="complianceFilter" class="${selectBaseClasses}"><option value="all" ${filterComplianceState === 'all' ? 'selected' : ''}>Todos</option><option value="${FindingStatus.COMPLIANT}" ${filterComplianceState === FindingStatus.COMPLIANT ? 'selected' : ''}>Conforme (${statusCounts[FindingStatus.COMPLIANT] || 0})</option><option value="${FindingStatus.NON_COMPLIANT}" ${filterComplianceState === FindingStatus.NON_COMPLIANT ? 'selected' : ''}>No Conforme (${statusCounts[FindingStatus.NON_COMPLIANT] || 0})</option></select></div>
            <div class="flex-1 min-w-[150px]"><label for="sortOrder" class="block text-xs text-slate-300 mb-1">Ordenar por:</label><select id="sortOrder" class="${selectBaseClasses}"><option value="severity" ${sortOrderState === 'severity' ? 'selected' : ''}>Severidad</option><option value="cis" ${sortOrderState === 'cis' ? 'selected' : ''}>Benchmark CIS</option><option value="status" ${sortOrderState === 'status' ? 'selected' : ''}>Estado</option></select></div>
        </div>
        <div id="findings-list-container-fleet-device"></div>
    `;

    return `<div id="fleet-device-details-card" class="mt-8">
                ${createCardHTML(`Resumen del Dispositivo: ${escapeHtml(analysisReport.fileName)}`, summaryContent)}
                <div class="mt-6">
                    ${createCardHTML('Hallazgos Detallados del Dispositivo', findingsContent)}
                </div>
            </div>`;
};

const renderFleetComparisonModalHTML = (state) => {
    const { fleetComparisonReport } = state;
    if (!fleetComparisonReport) return '';

    const { reportA, reportB, onlyInA, onlyInB, common } = fleetComparisonReport;
    
    const cardForDevice = (report) => `
        <div class="bg-slate-700/50 p-4 rounded-lg text-center">
            <h4 class="text-lg font-bold text-sky-300 truncate" title="${escapeHtml(report.fileName)}">${escapeHtml(report.fileName)}</h4>
            <p class="text-sm text-slate-400">Puntuación General</p>
            <p class="text-3xl font-semibold mt-1 ${report.summary.overallScore >= 75 ? 'text-green-400' : report.summary.overallScore >= 50 ? 'text-yellow-400' : 'text-red-400'}">
                ${report.summary.overallScore}%
            </p>
        </div>
    `;

    const subStateA = { ...state, analysisReport: reportA };
    const subStateB = { ...state, analysisReport: reportB };
    
    const findingsContentOnlyA = onlyInA.length > 0 ? onlyInA.map(f => renderFindingCardHTML(f, subStateA)).join('') : `<p class="text-slate-400 text-center py-4">Sin hallazgos únicos.</p>`;
    const findingsContentOnlyB = onlyInB.length > 0 ? onlyInB.map(f => renderFindingCardHTML(f, subStateB)).join('') : `<p class="text-slate-400 text-center py-4">Sin hallazgos únicos.</p>`;
    const findingsContentCommon = common.length > 0 ? common.map(f => renderFindingCardHTML(f, subStateA)).join('') : `<p class="text-slate-400 text-center py-4">Sin hallazgos comunes.</p>`;
    
    return `
    <div id="fleet-comparison-modal-overlay" class="fixed inset-0 bg-black/70 z-[100] flex items-center justify-center p-4" role="dialog" aria-modal="true" aria-labelledby="fleet-comparison-modal-title">
       <style>
        @keyframes fade-in { 0% { opacity: 0; } 100% { opacity: 1; } }
        @keyframes slide-up { 0% { opacity: 0; transform: translateY(20px); } 100% { opacity: 1; transform: translateY(0); } }
        .animate-fade-in { animation: fade-in 0.3s ease-out forwards; }
        .animate-slide-up { animation: slide-up 0.4s ease-out forwards; }
      </style>
      <div class="bg-slate-800 rounded-xl shadow-2xl w-full max-w-6xl max-h-[90vh] flex flex-col animate-fade-in">
        <div class="animate-slide-up" style="animation-delay: 0.1s; display: contents;">
          <header class="flex items-center justify-between p-4 border-b border-slate-700 flex-shrink-0">
            <h2 id="fleet-comparison-modal-title" class="text-xl font-bold text-sky-400">Comparando Dispositivos</h2>
            <button id="close-fleet-comparison-modal-button" class="text-slate-400 hover:text-white" aria-label="Cerrar modal">
              <svg class="w-6 h-6" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
            </button>
          </header>
          <div class="p-6 overflow-y-auto custom-scrollbar space-y-6">
            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                ${cardForDevice(reportA)}
                ${cardForDevice(reportB)}
            </div>
            
            <div class="space-y-4">
              ${createCardHTML(`Hallazgos solo en <span class="text-sky-300">${escapeHtml(reportA.fileName)}</span> (${onlyInA.length})`, findingsContentOnlyA)}
              ${createCardHTML(`Hallazgos solo en <span class="text-sky-300">${escapeHtml(reportB.fileName)}</span> (${onlyInB.length})`, findingsContentOnlyB)}
              ${createCardHTML(`Hallazgos Comunes (${common.length})`, findingsContentCommon)}
            </div>
          </div>
        </div>
      </div>
    </div>
  `;
};