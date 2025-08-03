import { Severity, FindingStatus } from '../constants.js';

export const checkGeneral = (configContent, addFinding, osType) => {
    const findings = [];
    const createFinding = (id, cis, title, severity, status, description, recommendation, affectedLines, geminiExplanation) => {
        findings.push({ id, cisBenchmark: cis, title, severity, status, description, recommendation, affectedLines, geminiExplanation });
    };

    // --- OS Version Check ---
    const osVersionRegex = /(?:Cisco IOS(?: XE)? Software, Version|version)\s+([^\s,]+)/i;
    const osVersionMatch = configContent.match(osVersionRegex);
    if (osVersionMatch) {
        const osName = osType === 'NX-OS' ? 'Cisco NX-OS' : 'Cisco IOS';
        const version = osVersionMatch[1].trim();
        createFinding('check-0', 'Vulnerability Management', 'Análisis de Versión del Sistema Operativo', Severity.HIGH, FindingStatus.NON_COMPLIANT,
            `Se detectó el sistema operativo '${osName}' en la versión '${version}'. Es crucial verificar esta versión contra la base de datos de vulnerabilidades de Cisco para identificar cualquier 'Advisory' de seguridad asociado.`,
            `Visite el sitio oficial de Cisco Software Checker e introduzca la siguiente información para obtener un listado de vulnerabilidades:\n\n- Sistema Operativo: ${osName}\n- Versión: ${version}\n\nPlanifique una actualización a una versión recomendada. Puede acceder a la herramienta aquí:\nhttps://sec.cloudapps.cisco.com/security/center/softwarechecker.x`,
            [osVersionMatch[0]],
            "Las versiones de software acumulan vulnerabilidades con el tiempo. Mantener el sistema operativo actualizado es una de las defensas más críticas."
        );
    }

    // --- Banner MOTD Check ---
    const bannerMotdMatch = configContent.includes("banner motd");
    if (!bannerMotdMatch) {
        createFinding('check-4', 'CIS 1.6.1', 'Configurar Banner MOTD', Severity.LOW, FindingStatus.NON_COMPLIANT,
            "No se encontró un banner MOTD (Message of the Day). Se debe configurar para advertir contra el acceso no autorizado.",
            "Configurar un banner MOTD:\nconfigure terminal\n banner motd #\n ADVERTENCIA: Acceso no autorizado prohibido.\n #\nend",
            undefined,
            "Un banner MOTD establece un aviso legal antes del inicio de sesión, disuadiendo el acceso no autorizado."
        );
    } else {
        createFinding('check-4', 'CIS 1.6.1', 'Banner MOTD Configurado', Severity.LOW, FindingStatus.COMPLIANT,
            "Un banner MOTD está configurado.",
            "Asegúrese de que el contenido del banner sea apropiado y cumpla con las políticas legales de su organización.",
            configContent.match(/^banner motd.*$/m)
        );
    }

    // --- IP CEF Check (IOS specific) ---
    if (osType === 'IOS') {
        const ipCef = configContent.includes("ip cef");
        if (!ipCef) {
            createFinding('check-17', 'Operational Best Practice', "Habilitar 'ip cef'", Severity.INFORMATIONAL, FindingStatus.NON_COMPLIANT,
                "'ip cef' (Cisco Express Forwarding) no está habilitado globalmente. CEF mejora el rendimiento del reenvío de paquetes.",
                "Habilitar CEF globalmente:\nconfigure terminal\n ip cef\nend",
                undefined,
                "CEF es un mecanismo avanzado de conmutación de paquetes que mejora el rendimiento y la estabilidad. Se recomienda tenerlo habilitado."
            );
        } else {
            createFinding('check-17', 'Operational Best Practice', "'ip cef' Habilitado", Severity.INFORMATIONAL, FindingStatus.COMPLIANT,
                "'ip cef' está habilitado globalmente.",
                "No se requiere acción.",
                configContent.match(/^ip cef$/m)
            );
        }
    } else {
         createFinding('check-17', 'Operational Best Practice', "Verificación de 'ip cef' no aplicable en NX-OS", Severity.INFORMATIONAL, FindingStatus.NOT_APPLICABLE,
            "El comando 'ip cef' es específico de IOS. NX-OS utiliza un plano de reenvío distribuido por hardware que está habilitado por defecto.",
            "No se requiere acción.",
            undefined
        );
    }

    // --- Domain Lookup Check ---
    const noIpDomainLookup = configContent.includes("no ip domain-lookup");
    if (!noIpDomainLookup) {
        createFinding('check-domain-lookup', 'Operational Best Practice', 'Deshabilitar Búsqueda DNS', Severity.INFORMATIONAL, FindingStatus.NON_COMPLIANT,
            "La búsqueda de DNS por la CLI ('ip domain-lookup') está habilitada. Esto puede causar retrasos operativos si se escribe mal un comando.",
            "Si el dispositivo no necesita resolver nombres de host desde la CLI, deshabilite la búsqueda de DNS:\nconfigure terminal\n no ip domain-lookup\nend",
            undefined,
            "Deshabilitar la búsqueda de DNS en dispositivos que no la necesitan (como la mayoría de los switches y routers internos) hace que la CLI sea más responsiva y evita que el dispositivo intente resolver comandos mal escritos como nombres de host."
        );
    } else {
        createFinding('check-domain-lookup', 'Operational Best Practice', 'Búsqueda DNS Deshabilitada', Severity.INFORMATIONAL, FindingStatus.COMPLIANT,
            "'no ip domain-lookup' está configurado.",
            "No se requiere acción.",
            configContent.match(/^no ip domain-lookup$/m)
        );
    }

    addFinding(findings);
};