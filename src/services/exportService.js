import { Severity, FindingStatus } from '../constants.js';
import { escapeHtml } from '../utils/escape.js';

// --- DYNAMIC IMPORTS ---
// Lazily load heavy libraries only when an export function is called.
// This makes the initial app load much faster and more robust.
const getJspdf = async () => {
    const { jsPDF } = await import('https://esm.sh/jspdf@2.5.1');
    const { default: autoTable } = await import('https://esm.sh/jspdf-autotable@3.8.2');
    return { jsPDF, autoTable };
};

const getFileSaver = async () => {
    const { default: saveAs } = await import('https://esm.sh/file-saver@2.0.5');
    return saveAs;
};


// --- HTML STYLING HELPERS ---
const getSeverityStylesForHtml = (severity) => {
  switch (severity) {
    case Severity.CRITICAL: return 'color: #ef4444; font-weight: bold;';
    case Severity.HIGH: return 'color: #f97316; font-weight: bold;';
    case Severity.MEDIUM: return 'color: #eab308;';
    case Severity.LOW: return 'color: #3b82f6;';
    case Severity.INFORMATIONAL: return 'color: #6b7280;';
    default: return '';
  }
};

const getStatusStylesForHtml = (status) => {
    switch (status) {
      case FindingStatus.COMPLIANT: return 'color: #22c55e;';
      case FindingStatus.NON_COMPLIANT: return 'color: #ef4444; font-weight: bold;';
      case FindingStatus.NOT_APPLICABLE: return 'color: #64748b;';
      case FindingStatus.ERROR: return 'color: #eab308;';
      default: return '';
    }
};

const getSeverityColorHex = (severity) => {
  switch (severity) {
    case Severity.CRITICAL: return '#ef4444';
    case Severity.HIGH: return '#f97316';
    case Severity.MEDIUM: return '#eab308';
    case Severity.LOW: return '#3b82f6';
    case Severity.INFORMATIONAL: return '#6b7280';
    default: return '#9ca3af';
  }
};

// --- SINGLE REPORT EXPORTERS ---
export const exportReportToHtml = async (report) => {
  const saveAs = await getFileSaver();
  let findingsHtml = '';
  const severityOrder = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFORMATIONAL];
  const sortedFindings = [...report.findings].sort((a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity));

  sortedFindings.forEach(finding => {
    findingsHtml += `
      <div class="finding-card" style="border-left: 5px solid ${getSeverityColorHex(finding.severity)};">
        <h3>${escapeHtml(finding.title)}</h3>
        <p><strong>ID:</strong> ${escapeHtml(finding.id)}</p>
        <p><strong>Benchmark CIS:</strong> ${escapeHtml(finding.cisBenchmark)}</p>
        <p><strong>Severidad:</strong> <span style="${getSeverityStylesForHtml(finding.severity)}">${escapeHtml(finding.severity)}</span></p>
        <p><strong>Estado:</strong> <span style="${getStatusStylesForHtml(finding.status)}">${escapeHtml(finding.status)}</span></p>
        <p><strong>Descripción:</strong> ${escapeHtml(finding.description)}</p>
        ${finding.geminiExplanation ? `<p><strong>Explicación Mejorada:</strong> <em>${escapeHtml(finding.geminiExplanation)}</em></p>` : ''}
        ${finding.affectedLines && finding.affectedLines.length > 0 ? `
          <p><strong>Configuración Afectada:</strong></p>
          <pre><code>${escapeHtml(finding.affectedLines.join('\n'))}</code></pre>
        ` : ''}
        <p><strong>Recomendación:</strong></p>
        <pre>${escapeHtml(finding.recommendation)}</pre>
      </div>
    `;
  });

  const htmlContent = `
    <!DOCTYPE html>
    <html lang="es">
    <head>
      <meta charset="UTF-8">
      <title>Reporte de Análisis de Hardening - ${escapeHtml(report.fileName)}</title>
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif, "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol"; margin: 20px; line-height: 1.6; background-color: #f0f2f5; color: #1f2937; }
        .container { background-color: #ffffff; padding: 25px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); max-width: 900px; margin: auto;}
        h1 { color: #1e40af; text-align: center; border-bottom: none; margin-bottom: 20px; font-size: 1.8em;}
        h2 { color: #1e3a8a; border-bottom: 1px solid #d1d5db; padding-bottom: 8px; margin-top: 30px; margin-bottom:15px; font-size: 1.4em;}
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 15px; margin-bottom: 25px; }
        .summary-item { background-color: #f9fafb; padding: 15px; border-radius: 6px; border: 1px solid #e5e7eb; }
        .summary-item p { margin: 4px 0; }
        .summary-item .label { font-size: 0.9em; color: #4b5563; }
        .summary-item .value { font-size: 1.1em; font-weight: 600; color: #111827; }
        .finding-card { background-color: #ffffff; border: 1px solid #e5e7eb; border-radius: 6px; margin-bottom: 20px; padding: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }
        .finding-card h3 { color: #1d4ed8; margin-top: 0; margin-bottom: 10px; font-size: 1.25em;}
        pre { background-color: #1e293b; color: #e2e8f0; padding: 12px; border-radius: 6px; overflow-x: auto; white-space: pre-wrap; word-wrap: break-word; font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, Courier, monospace; font-size: 0.875em;}
        code { font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, Courier, monospace; }
        .issues-by-severity { background-color: #f9fafb; padding: 15px; border-radius: 6px; border: 1px solid #e5e7eb; margin-bottom: 25px; }
        .issues-by-severity p.label { font-size: 1.1em; font-weight:600; color: #111827; margin-bottom: 10px;}
        .issues-by-severity div { margin-bottom: 6px; font-size: 0.95em;}
      </style>
    </head>
    <body>
      <div class="container">
        <h1>Reporte de Análisis de Hardening</h1>
        <section id="summary">
          <h2>Resumen del Análisis</h2>
          <div class="summary-grid">
            <div class="summary-item">
              <p class="label">Nombre del Archivo</p><p class="value">${escapeHtml(report.fileName)}</p>
            </div>
            <div class="summary-item">
              <p class="label">Fecha de Análisis</p><p class="value">${new Date(report.analysisDate).toLocaleString('es-ES', { dateStyle: 'long', timeStyle: 'short' })}</p>
            </div>
            <div class="summary-item">
              <p class="label">Verificaciones Totales</p><p class="value">${report.summary.totalChecks}</p>
            </div>
            <div class="summary-item">
              <p class="label">Problemas Encontrados</p><p class="value" style="color: #d946ef;">${report.summary.issuesFound}</p>
            </div>
            ${report.summary.overallScore !== undefined ? `
            <div class="summary-item">
              <p class="label">Puntuación General</p><p class="value" style="color: ${report.summary.overallScore >= 75 ? '#16a34a' : report.summary.overallScore >= 50 ? '#ca8a04' : '#dc2626'};">${report.summary.overallScore}%</p>
            </div>` : ''}
          </div>
          <div class="issues-by-severity">
             <p class="label">Problemas por Severidad:</p>
             ${severityOrder.map(sev => report.summary.bySeverity[sev] ? `<div><span style="${getSeverityStylesForHtml(sev)}">${escapeHtml(sev)}:</span> ${report.summary.bySeverity[sev]}</div>` : '').join('')}
          </div>
        </section>
        <section id="findings">
          <h2>Hallazgos Detallados</h2>
          ${findingsHtml}
        </section>
      </div>
    </body>
    </html>
  `;
  const blob = new Blob([htmlContent], { type: 'text/html;charset=utf-8' });
  saveAs(blob, `Reporte_Hardening_${report.fileName.replace(/\.[^/.]+$/, "")}.html`);
};

export const exportReportToPdf = async (report) => {
  const { jsPDF, autoTable } = await getJspdf();
  const saveAs = await getFileSaver();

  const doc = new jsPDF();
  const severityOrder = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFORMATIONAL];
  const sortedFindings = [...report.findings].sort((a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity));

  doc.setFontSize(18);
  doc.setTextColor(40, 58, 88); // Dark blue
  doc.text(`Reporte de Análisis: ${escapeHtml(report.fileName)}`, 14, 22);

  doc.setFontSize(14);
  doc.text("Resumen del Análisis", 14, 32);
  let summaryYPosition = 38;
  
  const summaryData = [
    ["Nombre del Archivo:", escapeHtml(report.fileName)],
    ["Fecha de Análisis:", new Date(report.analysisDate).toLocaleString('es-ES', { dateStyle: 'medium', timeStyle: 'short' })],
    ["Verificaciones Totales:", report.summary.totalChecks.toString()],
    ["Problemas Encontrados:", report.summary.issuesFound.toString()],
  ];
  if(report.summary.overallScore !== undefined) {
    summaryData.push(["Puntuación General:", `${report.summary.overallScore}%`]);
  }

  autoTable(doc, {
    startY: summaryYPosition,
    head: [['Detalle', 'Valor']],
    body: summaryData,
    theme: 'striped',
    styles: { fontSize: 9, cellPadding: 1.5 },
    headStyles: { fillColor: [75, 85, 99], textColor: [255,255,255] }, // Slate-600 like
    alternateRowStyles: {fillColor: [243, 244, 246]}, // Slate-100 like
  });
  summaryYPosition = doc.lastAutoTable.finalY + 8;

  doc.setFontSize(12);
  doc.text("Problemas por Severidad:", 14, summaryYPosition);
  summaryYPosition += 6;
  const severityBody = severityOrder
    .filter(sev => report.summary.bySeverity[sev])
    .map(sev => [escapeHtml(sev), report.summary.bySeverity[sev]?.toString() || '0']);
  
  autoTable(doc, {
    startY: summaryYPosition,
    head: [['Severidad', 'Cantidad']],
    body: severityBody,
    theme: 'grid',
    styles: { fontSize: 9, cellPadding: 1.5, lineWidth: 0.1, lineColor: [200,200,200] },
    headStyles: { fillColor: [55, 65, 81], textColor: [255,255,255]}, // Slate-700 like
    columnStyles: {
        0: { cellWidth: 35 },
        1: { cellWidth: 25, halign: 'center' }
    },
    didParseCell: function (data) {
        if (data.row.section === 'body' && data.column.index === 0) {
            const severity = data.cell.raw; 
            if (severity === Severity.CRITICAL) data.cell.styles.textColor = [220, 38, 38]; 
            else if (severity === Severity.HIGH) data.cell.styles.textColor = [234, 88, 12]; 
            else if (severity === Severity.MEDIUM) data.cell.styles.textColor = [202, 138, 4]; 
            else if (severity === Severity.LOW) data.cell.styles.textColor = [59, 130, 246];
            else if (severity === Severity.INFORMATIONAL) data.cell.styles.textColor = [107, 114, 128];
        }
    }
  });

  doc.addPage();
  doc.setFontSize(14);
  doc.text("Tabla Resumida de Hallazgos", 14, 20);
  const findingsSummaryBody = sortedFindings.map(f => [
    escapeHtml(f.id),
    escapeHtml(f.title),
    escapeHtml(f.severity),
    escapeHtml(f.status),
  ]);

  autoTable(doc, {
    startY: 28,
    head: [['ID', 'Título', 'Severidad', 'Estado']],
    body: findingsSummaryBody,
    theme: 'striped',
    styles: { fontSize: 8, cellPadding: 1.2, overflow: 'linebreak' },
    headStyles: { fillColor: [75, 85, 99], textColor: [255,255,255]},
    columnStyles: {
        0: {cellWidth: 25},
        1: {cellWidth: 'auto'},
        2: {cellWidth: 25},
        3: {cellWidth: 25},
    },
    didParseCell: function (data) {
        if (data.row.section === 'body') {
            if (data.column.index === 2) { 
                const severity = data.cell.raw;
                if (severity === Severity.CRITICAL) data.cell.styles.textColor = [220, 38, 38]; 
                else if (severity === Severity.HIGH) data.cell.styles.textColor = [234, 88, 12]; 
                else if (severity === Severity.MEDIUM) data.cell.styles.textColor = [202, 138, 4];
            }
            if (data.column.index === 3) {
                const status = data.cell.raw;
                if (status === FindingStatus.NON_COMPLIANT) data.cell.styles.textColor = [220, 38, 38];
                else if (status === FindingStatus.COMPLIANT) data.cell.styles.textColor = [22, 163, 74];
            }
        }
    }
  });
  
  sortedFindings.forEach((finding) => {
    doc.addPage();
    doc.setFontSize(12);
    doc.setTextColor(40,58,88);
    doc.text(`Detalle: ${escapeHtml(finding.id)} - ${escapeHtml(finding.title)}`, 14, 20);
    
    const detailTableBody = [
        ['ID', escapeHtml(finding.id)],
        ['Título', escapeHtml(finding.title)],
        ['Benchmark CIS', escapeHtml(finding.cisBenchmark)],
        ['Severidad', escapeHtml(finding.severity)],
        ['Estado', escapeHtml(finding.status)],
        ['Descripción', escapeHtml(finding.description)],
    ];
    if(finding.geminiExplanation) {
        detailTableBody.push(['Explicación Mejorada', escapeHtml(finding.geminiExplanation)]);
    }
    if(finding.affectedLines && finding.affectedLines.length > 0) {
        detailTableBody.push(['Config. Afectada', escapeHtml(finding.affectedLines.join('\n'))]);
    }
    detailTableBody.push(['Recomendación', escapeHtml(finding.recommendation)]);

    autoTable(doc, {
        startY: 28,
        head: [['Campo', 'Detalle']],
        body: detailTableBody,
        theme: 'grid',
        styles: { fontSize: 9, cellPadding: 2, lineWidth: 0.1, lineColor: [229,231,235], overflow: 'linebreak' },
        headStyles: { fillColor: [243, 244, 246], textColor: [55, 65, 81] }, 
        columnStyles: {
            0: { fontStyle: 'bold', cellWidth: 35 },
            1: { cellWidth: 'auto' }
        },
        didParseCell: function (data) {
             if (data.row.section === 'body') {
                const fieldName = data.row.cells[0].raw;
                if (fieldName === 'Descripción' || fieldName === 'Explicación Mejorada' || fieldName === 'Config. Afectada' || fieldName === 'Recomendación') {
                    data.cell.styles.font = 'courier'; 
                    data.cell.styles.fontSize = 8;
                }
                if (fieldName === 'Severidad') {
                    const severity = data.cell.raw;
                    if (severity === Severity.CRITICAL) data.cell.styles.textColor = [220, 38, 38];
                    else if (severity === Severity.HIGH) data.cell.styles.textColor = [234, 88, 12];
                    else if (severity === Severity.MEDIUM) data.cell.styles.textColor = [202, 138, 4];
                }
                if (fieldName === 'Estado') {
                    const status = data.cell.raw;
                    if (status === FindingStatus.NON_COMPLIANT) data.cell.styles.textColor = [220, 38, 38];
                    else if (status === FindingStatus.COMPLIANT) data.cell.styles.textColor = [22, 163, 74];
                }
            }
        }
    });
  });

  doc.save(`Reporte_Hardening_${report.fileName.replace(/\.[^/.]+$/, "")}.pdf`);
};


// --- COMPARISON REPORT EXPORTERS ---
export const exportComparisonReportToHtml = async (report) => {
    const saveAs = await getFileSaver();
    const renderFindingHtml = (finding, options = {}) => {
        const { isMitigated = false, isNew = false } = options;
        let cardStyle = `border-left: 5px solid ${getSeverityColorHex(finding.severity)};`;
        let titleStyle = `color: #1d4ed8;`;
        let statusText = escapeHtml(finding.status);
        let statusStyle = getStatusStylesForHtml(finding.status);

        if (isMitigated) {
            cardStyle = 'border-left: 5px solid #22c55e;';
            titleStyle = 'color: #16a34a;';
            statusText = 'Mitigado';
            statusStyle = 'color: #16a34a; font-weight: bold;';
        } else if (isNew) {
            titleStyle = 'color: #ca8a04;';
        }
        
        return `
          <div class="finding-card" style="${cardStyle}">
            <h3 style="${titleStyle}">${escapeHtml(finding.title)}</h3>
            <p><strong>ID:</strong> ${escapeHtml(finding.id)}</p>
            <p><strong>Benchmark CIS:</strong> ${escapeHtml(finding.cisBenchmark)}</p>
            <p><strong>Severidad:</strong> <span style="${getSeverityStylesForHtml(finding.severity)}">${escapeHtml(finding.severity)}</span></p>
            <p><strong>Estado:</strong> <span style="${statusStyle}">${statusText}</span></p>
            <p><strong>Descripción:</strong> ${escapeHtml(finding.description)}</p>
            ${finding.geminiExplanation ? `<p><strong>Explicación Mejorada:</strong> <em>${escapeHtml(finding.geminiExplanation)}</em></p>` : ''}
            ${finding.affectedLines && finding.affectedLines.length > 0 ? `
              <p><strong>Configuración Afectada:</strong></p>
              <pre><code>${escapeHtml(finding.affectedLines.join('\n'))}</code></pre>
            ` : ''}
            <p><strong>Recomendación:</strong></p>
            <pre>${escapeHtml(finding.recommendation)}</pre>
          </div>
        `;
    };

    const mitigatedHtml = report.mitigatedFindings.map(f => renderFindingHtml(f, { isMitigated: true })).join('');
    const pendingHtml = report.pendingFindings.map(f => renderFindingHtml(f)).join('');
    const newHtml = report.newFindings.map(f => renderFindingHtml(f, { isNew: true })).join('');

    const htmlContent = `
    <!DOCTYPE html>
    <html lang="es">
    <head>
      <meta charset="UTF-8">
      <title>Reporte de Comparación de Hardening</title>
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif, "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol"; margin: 20px; line-height: 1.6; background-color: #f0f2f5; color: #1f2937; }
        .container { background-color: #ffffff; padding: 25px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); max-width: 900px; margin: auto;}
        h1 { color: #1e40af; text-align: center; border-bottom: none; margin-bottom: 20px; font-size: 1.8em;}
        h2 { color: #1e3a8a; border-bottom: 1px solid #d1d5db; padding-bottom: 8px; margin-top: 30px; margin-bottom:15px; font-size: 1.4em;}
        h2.mitigated { color: #15803d; }
        h2.pending { color: #be123c; }
        h2.new { color: #ca8a04; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 25px; }
        .summary-item { background-color: #f9fafb; padding: 15px; border-radius: 6px; border: 1px solid #e5e7eb; text-align: center; }
        .summary-item .label { font-size: 0.9em; color: #4b5563; }
        .summary-item .value { font-size: 1.5em; font-weight: 600; color: #111827; }
        .summary-item .value.mitigated { color: #16a34a; }
        .summary-item .value.pending { color: #dc2626; }
        .summary-item .value.new { color: #d97706; }
        .finding-card { background-color: #ffffff; border: 1px solid #e5e7eb; border-radius: 6px; margin-bottom: 20px; padding: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }
        .finding-card h3 { margin-top: 0; margin-bottom: 10px; font-size: 1.25em;}
        pre { background-color: #1e293b; color: #e2e8f0; padding: 12px; border-radius: 6px; overflow-x: auto; white-space: pre-wrap; word-wrap: break-word; font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, Courier, monospace; font-size: 0.875em;}
        code { font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, Courier, monospace; }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>Reporte de Comparación de Hardening</h1>
        <section id="summary">
          <h2>Resumen de la Comparación</h2>
           <div class="summary-grid">
            <div class="summary-item"><p class="label">Antes</p><p class="value" style="font-size: 1em; font-weight: normal; word-break: break-all;">${escapeHtml(report.fileNameBefore)}</p></div>
            <div class="summary-item"><p class="label">Después</p><p class="value" style="font-size: 1em; font-weight: normal; word-break: break-all;">${escapeHtml(report.fileNameAfter)}</p></div>
            <div class="summary-item"><p class="label">Puntuación</p><p class="value">${report.scoreBefore}% &rarr; ${report.scoreAfter}%</p></div>
          </div>
          <div class="summary-grid">
            <div class="summary-item"><p class="label">Hallazgos Mitigados</p><p class="value mitigated">${report.mitigatedCount}</p></div>
            <div class="summary-item"><p class="label">Hallazgos Pendientes</p><p class="value pending">${report.pendingCount}</p></div>
            <div class="summary-item"><p class="label">Hallazgos Nuevos</p><p class="value new">${report.newCount}</p></div>
          </div>
        </section>
        
        ${report.mitigatedCount > 0 ? `<section>
          <h2 class="mitigated">Hallazgos Mitigados (${report.mitigatedCount})</h2>
          ${mitigatedHtml}
        </section>` : ''}
        
        ${report.pendingCount > 0 ? `<section>
          <h2 class="pending">Hallazgos Pendientes (${report.pendingCount})</h2>
          ${pendingHtml}
        </section>` : ''}

        ${report.newCount > 0 ? `<section>
          <h2 class="new">Hallazgos Nuevos (${report.newCount})</h2>
          ${newHtml}
        </section>`: ''}
      </div>
    </body>
    </html>
  `;
  const blob = new Blob([htmlContent], { type: 'text/html;charset=utf-8' });
  saveAs(blob, `Reporte_Comparacion_${report.fileNameAfter.replace(/\.[^/.]+$/, "")}.html`);
};

export const exportComparisonReportToPdf = async (report) => {
    const { jsPDF, autoTable } = await getJspdf();
    const saveAs = await getFileSaver();
    const doc = new jsPDF();

    doc.setFontSize(18);
    doc.setTextColor(40, 58, 88);
    doc.text("Reporte de Comparación de Hardening", 14, 22);

    autoTable(doc, {
        startY: 30,
        head: [['Detalle', 'Valor']],
        body: [
            ['Archivo "Antes"', escapeHtml(report.fileNameBefore)],
            ['Archivo "Después"', escapeHtml(report.fileNameAfter)],
            ['Puntuación General', `${report.scoreBefore}%  →  ${report.scoreAfter}%`],
            ['Hallazgos Mitigados', report.mitigatedCount.toString()],
            ['Hallazgos Pendientes', report.pendingCount.toString()],
            ['Hallazgos Nuevos', report.newCount.toString()],
        ],
        theme: 'striped',
        styles: { fontSize: 9 },
        headStyles: { fillColor: [75, 85, 99], textColor: [255, 255, 255] },
        didParseCell: (data) => {
            if (data.row.section === 'body') {
                if (data.row.cells[0].raw === 'Hallazgos Mitigados') data.row.cells[1].styles.textColor = [22, 163, 74];
                if (data.row.cells[0].raw === 'Hallazgos Pendientes') data.row.cells[1].styles.textColor = [220, 38, 38];
                if (data.row.cells[0].raw === 'Hallazgos Nuevos') data.row.cells[1].styles.textColor = [202, 138, 4];
            }
        }
    });

    const addFindingsToDoc = (title, findings, options) => {
        if (!findings || findings.length === 0) return;

        doc.addPage();
        doc.setFontSize(16);
        doc.setTextColor(options.titleColor[0], options.titleColor[1], options.titleColor[2]);
        doc.text(title, 14, 20);
        
        let yPos = 28;

        findings.forEach((finding) => {
            if (yPos > 250) { // Check if a new page is needed before drawing the next finding
                doc.addPage();
                yPos = 20; // Reset Y position for the new page
                doc.setFontSize(16);
                doc.setTextColor(options.titleColor[0], options.titleColor[1], options.titleColor[2]);
                doc.text(title + " (cont.)", 14, yPos);
                yPos += 8;
            }

            const detailTableBody = [
                ['ID', escapeHtml(finding.id)],
                ['Título', escapeHtml(finding.title)],
                ['Benchmark CIS', escapeHtml(finding.cisBenchmark)],
                ['Severidad', escapeHtml(finding.severity)],
                ['Descripción', escapeHtml(finding.description)],
            ];
             if(finding.geminiExplanation) detailTableBody.push(['Explicación Mejorada', escapeHtml(finding.geminiExplanation)]);
             if(finding.affectedLines && finding.affectedLines.length > 0) detailTableBody.push(['Config. Afectada', escapeHtml(finding.affectedLines.join('\n'))]);
             detailTableBody.push(['Recomendación', escapeHtml(finding.recommendation)]);
             
             autoTable(doc, {
                startY: yPos,
                head: [['Campo', 'Detalle']],
                body: detailTableBody,
                theme: 'grid',
                styles: { fontSize: 9, cellPadding: 2, overflow: 'linebreak' },
                headStyles: { fillColor: options.headFillColor, textColor: [50, 50, 50] },
                columnStyles: { 0: { fontStyle: 'bold', cellWidth: 35 } },
                didParseCell: (data) => {
                    if (data.row.section === 'body') {
                        const fieldName = data.row.cells[0].raw;
                        if (['Descripción', 'Explicación Mejorada', 'Config. Afectada', 'Recomendación'].includes(fieldName)) {
                            data.cell.styles.font = 'courier';
                            data.cell.styles.fontSize = 8;
                        }
                    }
                }
             });
             yPos = doc.lastAutoTable.finalY + 10;
        });
    };

    addFindingsToDoc("Hallazgos Mitigados", report.mitigatedFindings, { titleColor: [22, 163, 74], headFillColor: [209, 250, 229] });
    addFindingsToDoc("Hallazgos Pendientes", report.pendingFindings, { titleColor: [220, 38, 38], headFillColor: [254, 226, 226] });
    addFindingsToDoc("Hallazgos Nuevos", report.newFindings, { titleColor: [202, 138, 4], headFillColor: [254, 249, 195] });

    doc.save(`Reporte_Comparacion_${report.fileNameAfter.replace(/\.[^/.]+$/, "")}.pdf`);
};