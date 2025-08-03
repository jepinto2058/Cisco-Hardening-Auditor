import { Severity, FindingStatus } from '../constants.js';

export const checkVty = (configContent, addFinding, osType) => {
    const findings = [];
    const createFinding = (id, cis, title, severity, status, description, recommendation, affectedLines, geminiExplanation) => {
        findings.push({ id, cisBenchmark: cis, title, severity, status, description, recommendation, affectedLines, geminiExplanation });
    };

    const lineVtyRegex = /line vty (\d+(?: \d+)?)\s*([\s\S]*?)(?=\nline|\n!|$)/gi;
    let vtyMatch;
    let vtyBlocksFound = false;

    while ((vtyMatch = lineVtyRegex.exec(configContent)) !== null) {
        vtyBlocksFound = true;
        const vtyRange = vtyMatch[1];
        const vtyConfig = vtyMatch[2];
        const vtyLineHeader = `line vty ${vtyRange}`;

        // Check 1: Transport Input SSH (CIS 5.3.4)
        const transportInputMatch = vtyConfig.match(/transport input (.*)/i);
        if (transportInputMatch) {
            const protocols = transportInputMatch[1].trim().toLowerCase();
            if (protocols === 'ssh') {
                createFinding(`check-vty-transport-${vtyRange}`, 'CIS 5.3.4', `Líneas VTY ${vtyRange} Restringidas a SSH`, Severity.HIGH, FindingStatus.COMPLIANT,
                    `Las líneas VTY ${vtyRange} están correctamente restringidas para aceptar solo conexiones SSH.`,
                    "No se requiere acción.",
                    [`${vtyLineHeader}`, ` transport input ${protocols}`]);
            } else {
                createFinding(`check-vty-transport-${vtyRange}`, 'CIS 5.3.4', `Líneas VTY ${vtyRange} no Restringidas a SSH Únicamente`, Severity.HIGH, FindingStatus.NON_COMPLIANT,
                    `Las líneas VTY ${vtyRange} permiten protocolos inseguros o adicionales ('${protocols}'). Se debe permitir únicamente SSH para el acceso de gestión remota.`,
                    `Restringir VTY a solo SSH:\nconfigure terminal\n line vty ${vtyRange}\n  transport input ssh\n end`,
                    [`${vtyLineHeader}`, ` transport input ${protocols}`]);
            }
        } else {
            createFinding(`check-vty-transport-${vtyRange}`, 'CIS 5.3.4', `Líneas VTY ${vtyRange} sin Restricción de Transporte`, Severity.HIGH, FindingStatus.NON_COMPLIANT,
                `Las líneas VTY ${vtyRange} no tienen un 'transport input' configurado, lo que puede permitir el acceso a través de protocolos inseguros como Telnet por defecto.`,
                `Restringir VTY a solo SSH:\nconfigure terminal\n line vty ${vtyRange}\n  transport input ssh\n end`,
                [vtyLineHeader]);
        }

        // Check 2: Exec Timeout (CIS 5.3.5)
        const execTimeoutMatch = vtyConfig.match(/exec-timeout (\d+)(?: (\d+))?/i);
        if (!execTimeoutMatch) {
            createFinding(`check-vty-timeout-${vtyRange}`, 'CIS 5.3.5', `Configurar 'exec-timeout' en Líneas VTY ${vtyRange}`, Severity.LOW, FindingStatus.NON_COMPLIANT,
                `Las líneas VTY ${vtyRange} no tienen un timeout de sesión configurado ('exec-timeout'). Esto puede dejar sesiones de administrador abiertas indefinidamente.`,
                `Configure un timeout para cerrar sesiones inactivas:\nconfigure terminal\n line vty ${vtyRange}\n  exec-timeout 10 0\n end`,
                [vtyLineHeader],
                "Las sesiones de administrador inactivas y abiertas son un objetivo fácil para el acceso no autorizado si un terminal queda desatendido.");
        } else {
            const minutes = parseInt(execTimeoutMatch[1]);
            const seconds = execTimeoutMatch[2] ? parseInt(execTimeoutMatch[2]) : 0;
            if (minutes === 0 && seconds === 0) {
                createFinding(`check-vty-timeout-${vtyRange}`, 'CIS 5.3.5', `'exec-timeout' Deshabilitado en Líneas VTY ${vtyRange}`, Severity.LOW, FindingStatus.NON_COMPLIANT,
                    `El 'exec-timeout' en las líneas VTY ${vtyRange} está configurado en 0 0, lo que deshabilita el timeout de sesión.`,
                    `Configure un timeout con un valor razonable (ej. 10 minutos):\nconfigure terminal\n line vty ${vtyRange}\n  exec-timeout 10 0\n end`,
                    [`${vtyLineHeader}`, ` exec-timeout ${minutes} ${seconds === 0 ? '0' : seconds}`],
                    "Un timeout de 0 0 desactiva la función de cierre de sesión por inactividad, anulando esta medida de seguridad.");
            } else {
                createFinding(`check-vty-timeout-${vtyRange}`, 'CIS 5.3.5', `'exec-timeout' Configurado en Líneas VTY ${vtyRange}`, Severity.LOW, FindingStatus.COMPLIANT,
                    `Las líneas VTY ${vtyRange} tienen un timeout de sesión configurado en ${minutes} minuto(s) y ${seconds} segundo(s).`,
                    "Asegúrese de que este valor cumpla con la política de seguridad de su organización.",
                    [`${vtyLineHeader}`, ` exec-timeout ${minutes} ${seconds}`]);
            }
        }
        
        // Check 3: Access-Class (CIS 5.3.7)
        const accessClassMatch = vtyConfig.match(/access-class (\S+) in/i);
        if (!accessClassMatch) {
            createFinding(`check-vty-acl-${vtyRange}`, 'CIS 5.3.7', `ACL de Gestión no Aplicada a Líneas VTY ${vtyRange}`, Severity.HIGH, FindingStatus.NON_COMPLIANT,
                `Las líneas VTY ${vtyRange} no están protegidas por una lista de control de acceso (ACL). Esto permite que cualquier dirección IP intente conectarse.`,
                `Aplique una ACL para restringir el acceso solo a IPs de gestión de confianza:\nconfigure terminal\n line vty ${vtyRange}\n  access-class <ACL_NAME> in\nend\n\nExample ACL:\nip access-list standard <ACL_NAME>\n permit host 10.1.1.10\n deny any log\nend`,
                [vtyLineHeader],
                "No restringir el acceso a las interfaces de gestión es como dejar la puerta principal de un edificio sin seguridad. Una ACL actúa como un portero, solo permitiendo el acceso a IPs autorizadas.");
        } else {
            const aclName = accessClassMatch[1];
             createFinding(`check-vty-acl-${vtyRange}`, 'CIS 5.3.7', `ACL de Gestión Aplicada a Líneas VTY ${vtyRange}`, Severity.HIGH, FindingStatus.COMPLIANT,
                `Las líneas VTY ${vtyRange} están protegidas por la ACL '${aclName}'.`,
                `Verifique que la ACL '${aclName}' esté correctamente configurada para permitir solo las direcciones IP de gestión necesarias.`,
                [`${vtyLineHeader}`, ` access-class ${aclName} in`]);
        }

        // Check 4: Logging Synchronous (Best Practice)
        if (!vtyConfig.includes('logging synchronous')) {
            createFinding(`check-vty-logsync-${vtyRange}`, 'Operational Best Practice', `Configurar 'logging synchronous' en Líneas VTY ${vtyRange}`, Severity.INFORMATIONAL, FindingStatus.NON_COMPLIANT,
                `El comando 'logging synchronous' no está configurado en las líneas VTY ${vtyRange}. Sin él, los mensajes de log pueden interrumpir y desordenar la entrada de comandos en la CLI.`,
                `Mejore la usabilidad de la CLI configurando 'logging synchronous':\nconfigure terminal\n line vty ${vtyRange}\n  logging synchronous\n end`,
                [vtyLineHeader],
                "'logging synchronous' es un comando de calidad de vida para los administradores. Vuelve a imprimir la línea de comando actual después de que aparece un mensaje de log, evitando la confusión y los errores de tipeo.");
        } else {
             createFinding(`check-vty-logsync-${vtyRange}`, 'Operational Best Practice', `'logging synchronous' Configurado en Líneas VTY ${vtyRange}`, Severity.INFORMATIONAL, FindingStatus.COMPLIANT,
                `Las líneas VTY ${vtyRange} tienen 'logging synchronous' configurado, mejorando la experiencia de la CLI.`,
                `No se requiere acción.`,
                [`${vtyLineHeader}`, ` logging synchronous`]);
        }
    }

    if (!vtyBlocksFound) {
        createFinding('check-vty-existence', 'Core Configuration', 'No se encontraron Líneas VTY', Severity.HIGH, FindingStatus.ERROR,
            'No se encontraron bloques de configuración "line vty". Estos son esenciales para la gestión remota. Es posible que el archivo de configuración esté incompleto o sea de un dispositivo sin gestión remota.',
            'Verifique que el archivo de configuración sea completo y contenga las secciones "line vty 0 4", etc. Si el dispositivo no tiene gestión remota, este hallazgo puede ser ignorado.',
            undefined,
            'Las líneas VTY son las puertas virtuales a través de las cuales los administradores acceden al dispositivo remotamente. Si no existen, la gestión remota por CLI es imposible.');
    }

    // --- Auxiliary Port (AUX) Check ---
    const lineAuxRegex = /line aux 0\s*([\s\S]*?)(?=\nline|\n!|$)/i;
    const auxMatch = configContent.match(lineAuxRegex);

    if (auxMatch) {
        const auxConfig = auxMatch[1];
        const isSecure = auxConfig.includes("no exec") || auxConfig.includes("transport input none");
        if (isSecure) {
            createFinding('check-aux-port', 'CIS 1.5.1', 'Puerto AUX Asegurado o Deshabilitado', Severity.MEDIUM, FindingStatus.COMPLIANT,
                "El puerto auxiliar (line aux 0) está configurado de forma segura (deshabilitado).",
                "No se requiere acción. El puerto está correctamente desactivado para prevenir acceso no autorizado.",
                [auxMatch[0].split('\n')[0]]
            );
        } else {
            createFinding('check-aux-port', 'CIS 1.5.1', 'Asegurar Puerto AUX no Utilizado', Severity.MEDIUM, FindingStatus.NON_COMPLIANT,
                "El puerto auxiliar (line aux 0) está configurado pero no deshabilitado. Si no se utiliza, un puerto AUX activo puede ser un vector de ataque si se conecta un módem.",
                "Si el puerto AUX no se utiliza, deshabilítelo:\nconfigure terminal\n line aux 0\n  no exec\n  transport input none\nend",
                [auxMatch[0].split('\n')[0]],
                "Un puerto AUX activo puede ser una puerta trasera a la red si un atacante obtiene acceso físico y conecta un módem."
            );
        }
    } else {
        createFinding('check-aux-port', 'CIS 1.5.1', 'Puerto AUX no Configurado', Severity.MEDIUM, FindingStatus.COMPLIANT,
            "No se encontró una configuración explícita para 'line aux 0', lo cual es seguro si no está en uso.",
            "No se requiere acción."
        );
    }


    addFinding(findings);
};