import { Severity, FindingStatus } from '../constants.js';

export const checkRouting = (configContent, addFinding, osType) => {
    const findings = [];
    const createFinding = (id, cis, title, severity, status, description, recommendation, affectedLines, geminiExplanation) => {
        findings.push({ id, cisBenchmark: cis, title, severity, status, description, recommendation, affectedLines, geminiExplanation });
    };

    // --- Passive Interface Check ---
    const routerProtocolRegex = /router (eigrp|ospf|rip) .*\s*([\s\S]*?)(?=\n!|$)/gi;
    let routerMatch;
    while ((routerMatch = routerProtocolRegex.exec(configContent)) !== null) {
        const protocol = routerMatch[1];
        const routerConfig = routerMatch[2];
        const routerFullConfig = routerMatch[0];

        if (!routerConfig.includes("passive-interface default")) {
            createFinding(`check-passive-interface-${protocol}`, 'CIS 5.4.1', `Usar 'passive-interface default' en ${protocol.toUpperCase()}`, Severity.MEDIUM, FindingStatus.NON_COMPLIANT,
                `La configuración del router ${protocol.toUpperCase()} no utiliza 'passive-interface default'. Esto puede permitir que se formen adyacencias de enrutamiento en interfaces no confiables.`,
                `Establezca todas las interfaces como pasivas por defecto y luego habilite el protocolo solo en las interfaces necesarias:\nconfigure terminal\n router ${protocol} <ASN/ProcessID>\n  passive-interface default\n  no passive-interface <interfaz_troncal>\nend`,
                [routerFullConfig.split('\n')[0]],
                "'passive-interface default' previene fugas de información de enrutamiento y posibles ataques al no enviar actualizaciones por todas las interfaces."
            );
        } else {
            createFinding(`check-passive-interface-${protocol}`, 'CIS 5.4.1', `'passive-interface default' Usado en ${protocol.toUpperCase()}`, Severity.MEDIUM, FindingStatus.COMPLIANT,
                `El router ${protocol.toUpperCase()} está configurado para ser pasivo en todas las interfaces por defecto.`,
                "Asegúrese de que el protocolo esté habilitado explícitamente ('no passive-interface') solo en las interfaces donde se requiere.",
                routerConfig.match(/^.*passive-interface.*$/gm)
            );
        }
    }

    // --- Static Route Naming (IOS specific) ---
    if (osType === 'IOS') {
        const allStaticRoutesRegex = /^ip route (?!0\.0\.0\.0 0\.0\.0\.0).*$/gm;
        const allStaticRoutes = configContent.match(allStaticRoutesRegex) || [];
        const staticRoutesWithoutName = allStaticRoutes.filter(route => !/ name \S+/.test(route));

        if (staticRoutesWithoutName.length > 0) {
            createFinding('check-30', 'Operational Best Practice', 'Rutas Estáticas sin Nombre Descriptivo', Severity.LOW, FindingStatus.NON_COMPLIANT,
                `Se encontraron ${staticRoutesWithoutName.length} ruta(s) estática(s) sin un nombre descriptivo.`,
                "Añada un nombre a cada ruta estática para identificar su propósito. Ejemplo:\nip route 192.168.1.0 255.255.255.0 10.0.0.1 name RUTA_A_RED_ADMIN",
                staticRoutesWithoutName,
                "Nombrar las rutas facilita la gestión y la solución de problemas en tablas de enrutamiento complejas."
            );
        }
    } else {
        createFinding('check-30', 'Operational Best Practice', 'Nombres en Rutas Estáticas no Aplicable en NX-OS', Severity.LOW, FindingStatus.NOT_APPLICABLE,
            "La opción de nombrar rutas estáticas es específica de IOS. NX-OS no soporta esta característica.",
            "No se requiere acción.",
            undefined
        );
    }
    
    // --- Source Routing ---
    if (!configContent.includes("no ip source-route")) {
        createFinding('check-7', 'CIS 5.1.4', 'Deshabilitar Source Routing', Severity.MEDIUM, FindingStatus.NON_COMPLIANT,
          "No se encontró 'no ip source-route'. El source routing puede ser mal utilizado por atacantes.",
          "Deshabilitar source routing:\nconfigure terminal\n no ip source-route\nend",
          undefined,
          "El source routing permite que el originador de un paquete especifique la ruta, lo cual puede ser explotado para eludir firewalls."
        );
      } else {
        createFinding('check-7', 'CIS 5.1.4', 'Source Routing Deshabilitado', Severity.MEDIUM, FindingStatus.COMPLIANT,
          "'no ip source-route' está configurado.",
          "No se requiere acción.",
          configContent.match(/^no ip source-route$/m)
        );
      }

    addFinding(findings);
};