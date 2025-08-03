import { Severity, FindingStatus } from '../constants.js';

export const checkServices = (configContent, addFinding, osType) => {
    const findings = [];
    const createFinding = (id, cis, title, severity, status, description, recommendation, affectedLines, geminiExplanation) => {
        findings.push({ id, cisBenchmark: cis, title, severity, status, description, recommendation, affectedLines, geminiExplanation });
    };

    // --- HTTP/HTTPS Server ---
    const httpServerEnabled = configContent.match(/^ip http server$/im) && !configContent.match(/^no ip http server$/im);
    const httpsServerEnabled = configContent.match(/^ip http secure-server$/im);

    if (httpServerEnabled) {
        createFinding('check-3.1', 'CIS 4.1', 'Deshabilitar Servidor HTTP', Severity.HIGH, FindingStatus.NON_COMPLIANT, "El servidor HTTP ('ip http server') está habilitado. Transmite datos en texto plano.", "Deshabilite el servidor HTTP:\nconfigure terminal\n no ip http server\nend\nSi se requiere acceso web, use HTTPS.", configContent.match(/^ip http server$/im));
    } else {
        createFinding('check-3.1', 'CIS 4.1', 'Servidor HTTP Deshabilitado', Severity.HIGH, FindingStatus.COMPLIANT, "El servidor HTTP no está habilitado.", "No se requiere acción.", configContent.match(/^no ip http server$/m));
    }
    if (!httpsServerEnabled && httpServerEnabled) { // Only suggest HTTPS if HTTP is on
        createFinding('check-3.2', 'CIS 4.2', 'Habilitar Servidor HTTPS si se Necesita Gestión Web', Severity.MEDIUM, FindingStatus.NON_COMPLIANT, "Si se necesita gestión web, se debería usar 'ip http secure-server' en lugar de HTTP.", "Habilitar HTTPS:\nconfigure terminal\n ip http secure-server\nend");
    }

    // --- Finger Service ---
    if (configContent.match(/^ip finger$/im) && !configContent.match(/^no ip finger$/im)) {
        createFinding('check-8', 'CIS 4.4', 'Deshabilitar Servicio Finger', Severity.LOW, FindingStatus.NON_COMPLIANT, "El servicio Finger ('ip finger') está habilitado. Puede revelar información sobre usuarios.", "Deshabilitar Finger:\nconfigure terminal\n no ip finger\nend", configContent.match(/^ip finger$/im));
    } else {
        createFinding('check-8', 'CIS 4.4', 'Servicio Finger Deshabilitado', Severity.LOW, FindingStatus.COMPLIANT, "El servicio Finger está deshabilitado.", "No se requiere acción.", configContent.match(/^no ip finger$/m));
    }

    // --- IOS Specific Services ---
    if (osType === 'IOS') {
        if (!configContent.includes("no service tcp-small-servers")) {
            createFinding('check-27.1', 'CIS 4.6', 'Deshabilitar TCP Small Servers', Severity.LOW, FindingStatus.NON_COMPLIANT, "Estos servicios de diagnóstico (Echo, Chargen, Discard) pueden ser explotados.", "Deshabilitar:\nconfigure terminal\n no service tcp-small-servers\nend");
        }
        if (!configContent.includes("no service udp-small-servers")) {
            createFinding('check-27.2', 'CIS 4.7', 'Deshabilitar UDP Small Servers', Severity.LOW, FindingStatus.NON_COMPLIANT, "Estos servicios de diagnóstico (Echo, Chargen, Discard) pueden ser explotados.", "Deshabilitar:\nconfigure terminal\n no service udp-small-servers\nend");
        }
        if (!configContent.includes("service tcp-keepalives-in")) {
            createFinding('check-24.1', 'Best Practice', 'Habilitar Keepalives para Conexiones TCP Entrantes', Severity.LOW, FindingStatus.NON_COMPLIANT, "Ayuda a detectar y cerrar sesiones TCP inactivas, liberando recursos.", "Habilitar:\nconfigure terminal\n service tcp-keepalives-in\nend");
        } else {
            createFinding('check-24.1', 'Best Practice', 'Keepalives para Conexiones TCP Entrantes Habilitado', Severity.LOW, FindingStatus.COMPLIANT, "Las conexiones TCP entrantes utilizan keepalives para detectar y cerrar sesiones inactivas.", "No se requiere acción.", configContent.match(/^service tcp-keepalives-in$/m));
        }
        if (!configContent.includes("service tcp-keepalives-out")) {
            createFinding('check-24.2', 'Best Practice', 'Habilitar Keepalives para Conexiones TCP Salientes', Severity.LOW, FindingStatus.NON_COMPLIANT, "Ayuda a detectar cuando el otro extremo de una conexión se vuelve inalcanzable.", "Habilitar:\nconfigure terminal\n service tcp-keepalives-out\nend");
        } else {
            createFinding('check-24.2', 'Best Practice', 'Keepalives para Conexiones TCP Salientes Habilitado', Severity.LOW, FindingStatus.COMPLIANT, "Las conexiones TCP salientes utilizan keepalives para detectar contrapartes inalcanzables.", "No se requiere acción.", configContent.match(/^service tcp-keepalives-out$/m));
        }
         if (!configContent.includes("no service pad")) {
            createFinding('check-26', 'CIS 4.5', 'Deshabilitar Servicio PAD', Severity.LOW, FindingStatus.NON_COMPLIANT, "El servicio PAD (X.25) es obsoleto y no debería estar activo.", "Deshabilitar:\nconfigure terminal\n no service pad\nend");
        }
        if (configContent.includes("ip bootp server")) {
            createFinding('check-no-ip-bootp', 'CIS 4.8', 'Deshabilitar Servicio BOOTP Server', Severity.LOW, FindingStatus.NON_COMPLIANT, "El servicio BOOTP es obsoleto y debe ser deshabilitado.", "Deshabilitar:\nconfigure terminal\n no ip bootp server\nend", configContent.match(/ip bootp server/gi));
        }
    } else { // NX-OS
        const naServices = ['tcp-small-servers', 'udp-small-servers', 'tcp-keepalives', 'pad', 'bootp'];
        naServices.forEach(service => {
            createFinding(`check-na-${service}`, 'Best Practice', `Servicio '${service}' no aplicable en NX-OS`, Severity.INFORMATIONAL, FindingStatus.NOT_APPLICABLE, `El servicio '${service}' es específico de IOS o está obsoleto y no se encuentra en NX-OS.`, "No se requiere acción.", undefined);
        });
    }

    addFinding(findings);
};