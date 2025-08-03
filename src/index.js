



import { renderApp, initializeSummaryCharts, initializeFleetCharts } from './ui/views.js';
import { analyzeConfiguration } from './services/analysisService.js';
import { generateComparisonReport } from './services/comparisonService.js';
import { exportReportToHtml, exportReportToPdf, exportComparisonReportToHtml, exportComparisonReportToPdf } from './services/exportService.js';
import { Severity } from './constants.js';
import { calculateRiskLevel } from './utils/risk.js';

// --- GLOBAL STATE ---
export let state = {
    currentView: 'modeSelection', // 'modeSelection', 'singleAnalysis', 'retestAnalysis', 'fleetAnalysis'
    // Single Analysis State
    uploadedFile: null,
    fileContent: null,
    analysisReport: null,
    // Comparison Analysis State
    uploadedFileBefore: null,
    fileContentBefore: null,
    uploadedFileAfter: null,
    fileContentAfter: null,
    comparisonReport: null,
    fileUploadSpecificErrorBefore: null,
    fileUploadSpecificErrorAfter: null,
    // Fleet Analysis State
    fleetFiles: [],
    fleetReport: null,
    isLoadingFleet: false,
    fleetAnalysisProgress: { processed: 0, total: 0, currentFile: '' },
    selectedFleetDeviceReport: null,
    selectedFleetDeviceFileName: null,
    fleetDevicesForComparison: new Set(),
    fleetComparisonReport: null,
    // General State
    isLoading: false,
    currentError: null,
    dragActiveTarget: null, // 'before', 'after', 'single', 'fleet'
    filterSeverityState: 'all',
    filterComplianceState: 'all',
    sortOrderState: 'severity',
    isExportingPdf: false,
    expandedFindings: new Set(),
    isSummaryModalOpen: false,
    executiveSummary: '',
    riskLevel: null,
};

// --- WEB WORKER ---
let fleetWorker;
function initializeWorker() {
    fleetWorker = new Worker(new URL('./services/fleetAnalyzer.js', import.meta.url), { type: 'module' });

    fleetWorker.onmessage = (e) => {
        const { type, payload } = e.data;
        if (type === 'progress') {
            setState({ fleetAnalysisProgress: payload });
        } else if (type === 'complete') {
            setState({ fleetReport: payload, isLoadingFleet: false });
        } else if (type === 'error') {
            setState({ isLoadingFleet: false, currentError: payload.message });
        }
    };
}
initializeWorker();


// --- STATE MUTATORS ---
const setState = (newState) => {
    const wasModalOpen = state.isSummaryModalOpen;

    Object.assign(state, newState);
    renderApp(state);
    
    attachEventListeners();
    
    if (state.isSummaryModalOpen && !wasModalOpen) {
        initializeSummaryCharts(state);
    }

    // Always re-initialize fleet charts if the report is present,
    // as renderApp recreates the canvas elements.
    if (state.fleetReport) {
        initializeFleetCharts(state.fleetReport);
    }
};

// --- EVENT HANDLERS ---
const handleFileSelected = (selectedFile, targetId) => {
    const newState = {
        currentError: null,
        fileUploadSpecificErrorBefore: targetId !== 'before' ? state.fileUploadSpecificErrorBefore : null,
        fileUploadSpecificErrorAfter: targetId !== 'after' ? state.fileUploadSpecificErrorAfter : null,
    };
    setState(newState);

    if (!selectedFile) {
        return;
    }

    const setError = (msg) => {
        const errorState = {};
        if (targetId === 'single') errorState.currentError = msg;
        else if (targetId === 'before') errorState.fileUploadSpecificErrorBefore = msg;
        else if (targetId === 'after') errorState.fileUploadSpecificErrorAfter = msg;
        setState(errorState);
    };

    const isValidType = selectedFile.type === 'text/plain' || selectedFile.name.endsWith('.txt') || selectedFile.name.endsWith('.log') || selectedFile.name.endsWith('.cfg');
    if (!isValidType) return setError("Tipo de archivo no válido. Sube .txt, .log, .cfg.");

    const isValidSize = selectedFile.size <= 5 * 1024 * 1024;
    if (!isValidSize) return setError("El archivo es demasiado grande. Máx 5MB.");

    const reader = new FileReader();
    reader.onload = (e) => {
        const content = e.target?.result;
        const fileUpdate = {};
        if (targetId === 'single') {
            fileUpdate.uploadedFile = selectedFile;
            fileUpdate.fileContent = content;
            fileUpdate.analysisReport = null;
        } else if (targetId === 'before') {
            fileUpdate.uploadedFileBefore = selectedFile;
            fileUpdate.fileContentBefore = content;
        } else if (targetId === 'after') {
            fileUpdate.uploadedFileAfter = selectedFile;
            fileUpdate.fileContentAfter = content;
        }
        setState(fileUpdate);
    };
    reader.onerror = () => setError("Ocurrió un error al leer el archivo.");
    reader.readAsText(selectedFile);
};

const handleMultipleFilesSelected = (files) => {
    const validFiles = Array.from(files).filter(file => 
        (file.type === 'text/plain' || file.name.endsWith('.txt') || file.name.endsWith('.log') || file.name.endsWith('.cfg')) &&
        file.size <= 5 * 1024 * 1024
    );

    if (validFiles.length !== files.length) {
        setState({ currentError: "Algunos archivos fueron omitidos por tipo o tamaño inválido." });
    } else {
        setState({ currentError: null });
    }
    
    const newFiles = [...state.fleetFiles];
    for(const file of validFiles){
        if(!newFiles.some(f => f.name === file.name && f.lastModified === file.lastModified)){
            newFiles.push(file);
        }
    }

    setState({ fleetFiles: newFiles });
};


const handleDragOver = (e) => {
    e.preventDefault();
    e.stopPropagation();
    const targetId = e.currentTarget.querySelector('input[type=file]')?.dataset.target;
    if (targetId && state.dragActiveTarget !== targetId) {
        setState({ dragActiveTarget: targetId });
    }
};

const handleDragLeave = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.currentTarget && !e.currentTarget.contains(e.relatedTarget)) {
        if (state.dragActiveTarget) {
            setState({ dragActiveTarget: null });
        }
    }
};

const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setState({ dragActiveTarget: null });
    const targetId = e.currentTarget.querySelector('input[type=file]')?.dataset.target;
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
        if (targetId === 'fleet') {
            handleMultipleFilesSelected(e.dataTransfer.files);
        } else {
            handleFileSelected(e.dataTransfer.files[0], targetId);
        }
    }
};

const handleAnalyze = async () => {
    if (!state.fileContent || !state.uploadedFile) {
        return setState({ currentError: "Por favor, carga primero un archivo de configuración." });
    }
    setState({ isLoading: true, currentError: null });

    try {
        const report = await analyzeConfiguration(state.uploadedFile.name, state.fileContent);
        setState({ analysisReport: report, isLoading: false });
    } catch (err) {
        console.error("Analysis failed:", err);
        const errorMessage = err instanceof Error ? err.message : "Ocurrió un error desconocido durante el análisis.";
        setState({ isLoading: false, currentError: errorMessage, analysisReport: null });
    }
};

const handleCompare = async () => {
    if (!state.fileContentBefore || !state.fileContentAfter) {
        return setState({ currentError: "Por favor, carga ambos archivos para comparar." });
    }
    setState({ isLoading: true, currentError: null });

    try {
        const [reportBefore, reportAfter] = await Promise.all([
            analyzeConfiguration(state.uploadedFileBefore.name, state.fileContentBefore),
            analyzeConfiguration(state.uploadedFileAfter.name, state.fileContentAfter)
        ]);
        const report = generateComparisonReport(reportBefore, reportAfter);
        setState({ comparisonReport: report, isLoading: false });
    } catch (err) {
        console.error("Comparison failed:", err);
        const errorMessage = err instanceof Error ? err.message : "Ocurrió un error desconocido durante la comparación.";
        setState({ isLoading: false, currentError: errorMessage, comparisonReport: null });
    }
};

const handleAnalyzeFleet = async () => {
    if (state.fleetFiles.length === 0) {
        return setState({ currentError: "Por favor, carga al menos un archivo de configuración." });
    }
    setState({ isLoadingFleet: true, currentError: null, fleetReport: null });
    fleetWorker.postMessage({ type: 'start', files: state.fleetFiles });
};

const handleClear = () => {
    setState({
        currentView: 'modeSelection',
        uploadedFile: null, fileContent: null, analysisReport: null,
        uploadedFileBefore: null, fileContentBefore: null,
        uploadedFileAfter: null, fileContentAfter: null,
        comparisonReport: null, currentError: null,
        fileUploadSpecificErrorBefore: null, fileUploadSpecificErrorAfter: null,
        isLoading: false, isExportingPdf: false, dragActiveTarget: null,
        expandedFindings: new Set(),
        filterSeverityState: 'all', filterComplianceState: 'all', sortOrderState: 'severity',
        isSummaryModalOpen: false, executiveSummary: '', riskLevel: null,
        fleetFiles: [], fleetReport: null, isLoadingFleet: false, 
        fleetAnalysisProgress: { processed: 0, total: 0, currentFile: '' },
        selectedFleetDeviceReport: null,
        selectedFleetDeviceFileName: null,
        fleetDevicesForComparison: new Set(),
        fleetComparisonReport: null,
    });
};

const handleExport = async (exportFn, report) => {
    if (report) {
        setState({ isExportingPdf: true, currentError: null });
        try {
            await exportFn(report);
        } catch (error) {
            console.error("Export failed:", error);
            const errorMessage = `Falló la exportación del reporte. Es posible que haya un problema de red para cargar las librerías o un error interno. Por favor, inténtelo de nuevo. \nError: ${error.message}`;
            setState({ currentError: errorMessage });
        } finally {
            setState({ isExportingPdf: false });
        }
    }
};

const handleFilterChange = (e) => {
    setState({ filterSeverityState: e.target.value });
};

const handleComplianceFilterChange = (e) => {
    setState({ filterComplianceState: e.target.value });
};

const handleSortOrderChange = (e) => {
    setState({ sortOrderState: e.target.value });
};

const handleFindingToggle = (findingId) => {
    const newExpandedFindings = new Set(state.expandedFindings);
    if (newExpandedFindings.has(findingId)) {
        newExpandedFindings.delete(findingId);
    } else {
        newExpandedFindings.add(findingId);
    }
    setState({ expandedFindings: newExpandedFindings });
};

const handleOpenSummaryModal = () => {
    const reportToSummarize = state.selectedFleetDeviceReport || state.analysisReport;
    if (!reportToSummarize) return;

    const riskLevel = calculateRiskLevel(reportToSummarize);
    const summaryText = generateExecutiveSummary(reportToSummarize, riskLevel);
    setState({ isSummaryModalOpen: true, executiveSummary: summaryText, riskLevel: riskLevel });
};

const handleCloseSummaryModal = () => {
    setState({ isSummaryModalOpen: false });
};

const handleSelectFleetDevice = async (fileName) => {
    if (state.selectedFleetDeviceFileName === fileName) {
        return handleCloseFleetDeviceDetails();
    }

    setState({ isLoading: true, selectedFleetDeviceReport: null });
    try {
        const report = await localforage.getItem(fileName);
        if (report) {
            setState({
                selectedFleetDeviceReport: report,
                selectedFleetDeviceFileName: fileName,
                isLoading: false,
                expandedFindings: new Set(),
                filterSeverityState: 'all',
                filterComplianceState: 'all',
            });
            setTimeout(() => {
                document.getElementById('fleet-device-details-card')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }, 100);
        } else {
            throw new Error('Reporte no encontrado en almacenamiento local.');
        }
    } catch(err) {
        setState({ currentError: err.message, isLoading: false, selectedFleetDeviceFileName: null });
    }
};

const handleCloseFleetDeviceDetails = () => {
    const fleetTableCard = document.getElementById('fleet-device-table-card');
    if (fleetTableCard) {
        fleetTableCard.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
    setState({ selectedFleetDeviceReport: null, selectedFleetDeviceFileName: null });
};

const handleToggleFleetDeviceForComparison = (fileName) => {
    const newSelectionSet = new Set(state.fleetDevicesForComparison);
    if (newSelectionSet.has(fileName)) {
        newSelectionSet.delete(fileName);
    } else {
        newSelectionSet.add(fileName);
    }
    setState({ fleetDevicesForComparison: newSelectionSet });
};

const handleCompareSelectedFleetDevices = async () => {
    if (state.fleetDevicesForComparison.size !== 2) return;
    
    setState({ isLoading: true, fleetComparisonReport: null, currentError: null });

    try {
        const [fileNameA, fileNameB] = Array.from(state.fleetDevicesForComparison);
        const [reportA, reportB] = await Promise.all([
            localforage.getItem(fileNameA),
            localforage.getItem(fileNameB)
        ]);

        if (!reportA || !reportB) {
            throw new Error("No se pudieron cargar los reportes de los dispositivos seleccionados.");
        }

        const { generateDeviceComparisonReport } = await import('./services/comparisonService.js');
        const comparisonReport = generateDeviceComparisonReport(reportA, reportB);
        
        setState({ fleetComparisonReport: comparisonReport, isLoading: false, expandedFindings: new Set() });

    } catch(err) {
        console.error("Fleet comparison failed:", err);
        setState({ currentError: err.message, isLoading: false });
    }
};

const handleCloseFleetComparisonModal = () => {
    setState({ fleetComparisonReport: null });
};

const generateExecutiveSummary = (report, riskLevel) => {
    if (!report || !report.summary || !riskLevel) return "No se pudo generar el resumen ejecutivo.";
    const { overallScore, bySeverity } = report.summary;
    const criticals = bySeverity[Severity.CRITICAL] || 0;
    const highs = bySeverity[Severity.HIGH] || 0;

    let posture;
    if (overallScore >= 90) posture = "una postura de seguridad EXCELENTE";
    else if (overallScore >= 75) posture = "una postura de seguridad SÓLIDA";
    else if (overallScore >= 50) posture = "una postura de seguridad ACEPTABLE, pero con áreas de mejora significativas";
    else posture = "una postura de seguridad DÉBIL que requiere atención inmediata";

    let mainConcerns;
    if (criticals > 0 && highs > 0) mainConcerns = `Se identificaron ${criticals} problema(s) CRÍTICO(S) y ${highs} problema(s) ALTO(S).`;
    else if (criticals > 0) mainConcerns = `Se identificó ${criticals} problema(s) CRÍTICO(S).`;
    else if (highs > 0) mainConcerns = `Se identificaron ${highs} problema(s) ALTO(S).`;
    else mainConcerns = "No se encontraron problemas críticos o altos.";

    let recommendations;
    if (criticals > 0) recommendations = "La prioridad MÁXIMA es mitigar los hallazgos CRÍTICOS para prevenir brechas de seguridad graves.";
    else if (highs > 0) recommendations = "Se recomienda enfocar los esfuerzos en solucionar los hallazgos de severidad ALTA para reducir significativamente la superficie de ataque.";
    else recommendations = "La recomendación principal es revisar los hallazgos de severidad media y baja para fortalecer aún más la configuración.";

    return `El análisis del dispositivo revela ${posture}, con un nivel de riesgo general evaluado como ${riskLevel.text}. Con una puntuación de ${overallScore}%, ${mainConcerns} ${recommendations}`;
};


// --- EVENT ATTACHMENT ---
const attachEventListeners = () => {
    const root = document.getElementById('root');
    if (!root) return;

    // Use a single, delegated event listener for clicks
    root.onclick = (e) => {
        const target = e.target;
        if (target.closest('#select-single-analysis')) return setState({ currentView: 'singleAnalysis' });
        if (target.closest('#select-retest-analysis')) return setState({ currentView: 'retestAnalysis' });
        if (target.closest('#select-fleet-analysis')) return setState({ currentView: 'fleetAnalysis' });
        if (target.closest('#back-to-mode-selection')) return handleClear();
        if (target.closest('#analyze-button')) return handleAnalyze();
        if (target.closest('#compare-button')) return handleCompare();
        if (target.closest('#analyze-fleet-button')) return handleAnalyzeFleet();
        if (target.closest('#analyze-another-button')) return handleClear();
        if (target.closest('#clear-file-button')) return setState({ uploadedFile: null, fileContent: null, currentError: null });
        if (target.closest('#clear-file-button-before')) return setState({ uploadedFileBefore: null, fileContentBefore: null, fileUploadSpecificErrorBefore: null });
        if (target.closest('#clear-file-button-after')) return setState({ uploadedFileAfter: null, fileContentAfter: null, fileUploadSpecificErrorAfter: null });
        if (target.closest('#export-html-button')) return exportReportToHtml(state.analysisReport);
        if (target.closest('#export-pdf-button')) return handleExport(exportReportToPdf, state.analysisReport);
        if (target.closest('#export-comparison-html-button')) return exportComparisonReportToHtml(state.comparisonReport);
        if (target.closest('#export-comparison-pdf-button')) return handleExport(exportComparisonReportToPdf, state.comparisonReport);
        if (target.closest('#summary-button')) return handleOpenSummaryModal();
        if (target.closest('#close-fleet-device-details-button')) return handleCloseFleetDeviceDetails();
        if (target.closest('#close-summary-modal-button') || target.matches('#summary-modal-overlay')) {
             return handleCloseSummaryModal();
        }
        if (target.closest('#compare-fleet-devices-button')) return handleCompareSelectedFleetDevices();
        if (target.closest('#close-fleet-comparison-modal-button') || target.matches('#fleet-comparison-modal-overlay')) {
            return handleCloseFleetComparisonModal();
        }
        
        const findingHeader = target.closest('.finding-header');
        if (findingHeader) {
            const findingId = findingHeader.closest('[data-finding-id]')?.dataset.findingId;
            if (findingId) handleFindingToggle(findingId);
        }

        const viewDetailsButton = target.closest('.view-fleet-device-details-button');
        if (viewDetailsButton) {
            const fileName = viewDetailsButton.dataset.filename;
            if (fileName) handleSelectFleetDevice(fileName);
        }

        const removeFleetFileButton = target.closest('.remove-fleet-file');
        if(removeFleetFileButton){
            const fileNameToRemove = removeFleetFileButton.dataset.filename;
            setState({ fleetFiles: state.fleetFiles.filter(f => f.name !== fileNameToRemove) });
        }
    };

    // Delegated listener for change events
    root.onchange = (e) => {
        const target = e.target;
        if (target.matches('#severityFilter')) return handleFilterChange(e);
        if (target.matches('#complianceFilter')) return handleComplianceFilterChange(e);
        if (target.matches('#sortOrder')) return handleSortOrderChange(e);
        if (target.matches('#dropzone-file-single')) return handleFileSelected(e.target.files[0], 'single');
        if (target.matches('#dropzone-file-before')) return handleFileSelected(e.target.files[0], 'before');
        if (target.matches('#dropzone-file-after')) return handleFileSelected(e.target.files[0], 'after');
        if (target.matches('#dropzone-file-fleet')) return handleMultipleFilesSelected(e.target.files);
        if (target.matches('.fleet-compare-checkbox')) {
            const fileName = target.dataset.filename;
            if (fileName) handleToggleFleetDeviceForComparison(fileName);
        }
    };

    // Delegated listener for keyboard accessibility on findings
    root.onkeypress = (e) => {
        const findingHeader = e.target.closest('.finding-header');
        if (findingHeader && (e.key === 'Enter' || e.key === ' ')) {
            e.preventDefault();
            const findingId = findingHeader.closest('[data-finding-id]')?.dataset.findingId;
            if (findingId) handleFindingToggle(findingId);
        }
    };
    
    // Direct attachment for drag/drop listeners, as they need to be on specific elements
    ['#dropzone-label-single', '#dropzone-label-before', '#dropzone-label-after', '#dropzone-label-fleet'].forEach(id => {
        const el = document.querySelector(id);
        if(el){
            el.ondragenter = handleDragOver;
            el.ondragleave = handleDragLeave;
            el.ondragover = handleDragOver;
            el.ondrop = handleDrop;
        }
    });
};

// --- INITIALIZATION ---
// Initial render and listener attachment
setState({});