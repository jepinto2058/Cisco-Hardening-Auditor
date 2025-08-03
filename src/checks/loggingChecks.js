import { Severity, FindingStatus } from '../constants.js';

export const checkLoggingAndNtp = (configContent, addFinding, osType) => {
    const findings = [];
    const createFinding = (id, cis, title, severity, status, description, recommendation, affectedLines, geminiExplanation) => {
        findings.push({ id, cisBenchmark: cis, title, severity, status, description, recommendation, affectedLines, geminiExplanation });
    };

    // --- Logging Checks ---
    const loggingBufferedMatch = configContent.match(/logging buffered (\d+)/i);
    if (!loggingBufferedMatch) {
        createFinding('check-5.1', 'CIS 3.1', 'Habilitar Logging Buffered', Severity.MEDIUM, FindingStatus.NON_COMPLIANT, "No se encontró 'logging buffered'. Es importante para almacenar logs localmente.", "Habilitar logging buffered:\nconfigure terminal\n logging buffered 8192 debugging\nend", undefined, "El logging local en buffer es vital para el análisis de problemas y eventos de seguridad directamente en el dispositivo.");
    } else if (parseInt(loggingBufferedMatch[1]) < 8192) {
        createFinding('check-5.1', 'CIS 3.1', 'Aumentar Tamaño del Buffer de Logging', Severity.LOW, FindingStatus.NON_COMPLIANT, `El buffer de logging (${loggingBufferedMatch[1]}) es pequeño. Se recomienda al menos 8192 bytes.`, "Aumentar el tamaño del buffer:\nconfigure terminal\n logging buffered 8192 debugging\nend", [loggingBufferedMatch[0]]);
    } else {
        createFinding('check-5.1', 'CIS 3.1', 'Logging Buffered Configurado Adecuadamente', Severity.MEDIUM, FindingStatus.COMPLIANT, `Logging buffered está configurado con un tamaño de ${loggingBufferedMatch[1]}.`, "No se requiere acción.", [loggingBufferedMatch[0]]);
    }

    // --- Remote Syslog Server Checks (IOS vs NX-OS) ---
    const remoteLoggingCommand = osType === 'IOS' ? 'logging host' : 'logging server';
    const remoteLoggingRegex = new RegExp(`^${remoteLoggingCommand}`, 'im');
    const isRemoteLoggingConfigured = remoteLoggingRegex.test(configContent);
    
    if (isRemoteLoggingConfigured) {
        const remoteLogLines = configContent.match(new RegExp(`^${remoteLoggingCommand}.*`, 'gm')) || [];
        
        // Check 1: Secure Transport
        const secureTransportRegex = /transport\s+tcp/i;
        const isSecureTransportConfigured = remoteLogLines.some(line => secureTransportRegex.test(line));

        if (!isSecureTransportConfigured) {
            createFinding('check-syslog-secure', 'CIS 3.5', 'Configurar Envío Seguro de Logs a Servidor Remoto', Severity.HIGH, FindingStatus.NON_COMPLIANT, 
                "Syslog está configurado, pero no utiliza un transporte seguro (TCP/TLS). Los logs enviados vía UDP están en texto plano y pueden ser interceptados.", 
                `Configure Syslog sobre un transporte TCP (y preferiblemente TLS si es soportado).\nEjemplo:\n${remoteLoggingCommand} <IP_SERVIDOR> transport tcp`, 
                remoteLogLines, 
                "Enviar logs sin cifrar por la red es como enviar postales con secretos. Cualquiera en la ruta puede leerlos. Usar TCP es el primer paso, y TLS (cuando es posible) provee cifrado completo.");
        } else {
             createFinding('check-syslog-secure', 'CIS 3.5', 'Envío Seguro de Logs a Servidor Remoto Configurado', Severity.HIGH, FindingStatus.COMPLIANT, 
                "Syslog está configurado para usar un transporte TCP, lo que es una mejora sobre UDP.", 
                "Para mayor seguridad, asegúrese de que la conexión esté protegida con TLS si la versión del sistema operativo y el servidor de syslog lo soportan.", 
                remoteLogLines.filter(line => secureTransportRegex.test(line)));
        }

        // Check 2: Source Interface
        if (!configContent.includes("logging source-interface")) {
            createFinding('check-5.4', 'CIS 3.2.1', 'Configurar Interfaz Fuente para Logging', Severity.LOW, FindingStatus.NON_COMPLIANT, 
            "Se configuró un servidor syslog pero no una interfaz fuente. Esto asegura que los mensajes usen una IP predecible.", 
            "Especificar una interfaz fuente para logging (usualmente Loopback):\nconfigure terminal\n logging source-interface Loopback0\nend", 
            undefined, 
            "Usar una interfaz fuente (como una Loopback) garantiza que los logs siempre se originen desde la misma IP, simplificando las reglas de firewall y la identificación del dispositivo en el servidor de logs.");
        } else {
            createFinding('check-5.4', 'CIS 3.2.1', 'Interfaz Fuente para Logging Configurada', Severity.LOW, FindingStatus.COMPLIANT, 
                "Se ha configurado una interfaz fuente para el envío de logs.", 
                "No se requiere acción.", 
                configContent.match(/^logging source-interface.*$/m));
        }
        
        // Check 3: Logging Level for remote server
        if (osType === 'IOS') {
            if (!configContent.match(/logging trap (\w+)/i)) {
                createFinding('check-5.2', 'CIS 3.3', 'Configurar Nivel de Logging para Syslog (Trap)', Severity.LOW, FindingStatus.NON_COMPLIANT, 
                "No se configuró el nivel de severidad para los mensajes enviados a servidores syslog ('logging trap').", 
                "Establecer el nivel de logging trap:\nconfigure terminal\n logging trap informational\nend", undefined, "Definir un nivel de 'logging trap' asegura que se envíen logs con la granularidad adecuada a los servidores remotos.");
            }
        } else { // NX-OS
            if (!configContent.match(/logging level syslog (\d+|[a-z]+)/i)) {
                createFinding('check-5.2-nxos', 'CIS 3.3', 'Configurar Nivel de Logging para Syslog (NX-OS)', Severity.LOW, FindingStatus.NON_COMPLIANT, 
                "No se configuró un nivel de severidad explícito para los mensajes enviados a servidores syslog ('logging level syslog'). El dispositivo usará el nivel por defecto.", 
                "Establecer el nivel de logging para syslog:\nconfigure terminal\n logging level syslog 6\nend (6 = informational)", undefined, "Definir un nivel explícito para syslog asegura que se envíen logs con la granularidad adecuada a los servidores remotos.");
            }
        }
    } else {
        createFinding('check-syslog-existence', 'CIS 3.5', 'No se ha Configurado Servidor de Syslog Remoto', Severity.HIGH, FindingStatus.NON_COMPLIANT, 
        "No se ha configurado ningún servidor de Syslog remoto. La centralización de logs es fundamental para la monitorización de la seguridad y el análisis forense.", 
        `Configure un servidor de logs remoto, preferiblemente usando un transporte seguro.\nEjemplo: ${remoteLoggingCommand} <IP_SERVIDOR>`, undefined);
    }
    
    // --- Timestamps Check ---
    if (osType === 'IOS') {
        const serviceTimestampsDebug = configContent.includes("service timestamps debug datetime msec");
        const serviceTimestampsLog = configContent.includes("service timestamps log datetime msec");
        if (!serviceTimestampsDebug || !serviceTimestampsLog) {
            createFinding('check-log-timestamps', 'CIS 3.6', 'Habilitar Timestamps Precisos para Logs', Severity.LOW, FindingStatus.NON_COMPLIANT, "No se han configurado timestamps precisos (con milisegundos) para los mensajes de debug y log. Esto es crucial para la correlación de eventos.", "Habilitar timestamps precisos:\nconfigure terminal\n service timestamps debug datetime msec\n service timestamps log datetime msec\nend", undefined, "Sin marcas de tiempo precisas, correlacionar eventos entre dispositivos durante un incidente se vuelve casi imposible.");
        } else {
            createFinding('check-log-timestamps', 'CIS 3.6', 'Timestamps Precisos para Logs Habilitados', Severity.LOW, FindingStatus.COMPLIANT, "'service timestamps' para debug y log están configurados con precisión.", "No se requiere acción.", configContent.match(/^service timestamps (debug|log) datetime msec$/gm));
        }
    } else { // NX-OS
        createFinding('check-log-timestamps-nxos', 'CIS 3.6', 'Verificación de Timestamps no Aplicable a NX-OS', Severity.LOW, FindingStatus.NOT_APPLICABLE, "El comando 'service timestamps' es específico de IOS. NX-OS habilita timestamps por defecto y utiliza 'logging timestamp' para su configuración.", "Verifique que los timestamps en los logs de NX-OS tengan la granularidad necesaria (ej. milisegundos).", undefined);
    }
    
    // --- NTP Checks ---
    const ntpServerMatch = configContent.match(/ntp server .+/gi);
    if (!ntpServerMatch) {
        createFinding('check-6.1', 'CIS 2.1.1', 'Configurar Servidores NTP', Severity.MEDIUM, FindingStatus.NON_COMPLIANT, "No se configuraron servidores NTP. La sincronización de tiempo es esencial para la correlación de logs.", "Configurar servidores NTP confiables:\nconfigure terminal\n ntp server <IP_SERVIDOR_NTP_1>\n ntp server <IP_SERVIDOR_NTP_2>\nend", undefined, "La sincronización horaria precisa a través de NTP es crítica para la validez de los logs y la correlación de eventos de seguridad.");
    } else {
        createFinding('check-6.1', 'CIS 2.1.1', 'Servidores NTP Configurados', Severity.MEDIUM, FindingStatus.COMPLIANT, "Servidores NTP están configurados.", "Asegúrese de que los servidores NTP sean confiables y considere usar redundancia.", ntpServerMatch);
    }
    
    addFinding(findings);
};