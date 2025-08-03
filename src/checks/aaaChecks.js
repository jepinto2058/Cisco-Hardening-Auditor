import { Severity, FindingStatus } from '../constants.js';

export const checkAaa = (configContent, addFinding, osType) => {
    const findings = [];

    const createFinding = (id, cis, title, severity, status, description, recommendation, affectedLines, geminiExplanation) => {
        findings.push({ id, cisBenchmark: cis, title, severity, status, description, recommendation, affectedLines, geminiExplanation });
    };

    const aaaNewModel = configContent.includes("aaa new-model");
    if (!aaaNewModel) {
        createFinding('check-11.1', 'CIS 1.3.1', "Habilitar 'aaa new-model'", Severity.HIGH, FindingStatus.NON_COMPLIANT,
            "'aaa new-model' no está habilitado. AAA es fundamental para la autenticación, autorización y auditoría centralizadas.",
            "Habilitar AAA:\nconfigure terminal\n aaa new-model\nend\nLuego, configurar métodos de autenticación, autorización y accounting.",
            undefined,
            "'aaa new-model' activa el framework AAA, permitiendo políticas de acceso granulares y gestión centralizada de usuarios, lo cual es esencial para la seguridad."
        );
    } else {
        createFinding('check-11.1', 'CIS 1.3.1', "'aaa new-model' Habilitado", Severity.HIGH, FindingStatus.COMPLIANT,
            "'aaa new-model' está habilitado.",
            "Asegúrese de que los métodos AAA para login, exec, etc., estén correctamente configurados para usar servidores remotos (TACACS+/RADIUS) y/o listas locales como respaldo.",
            configContent.match(/^aaa new-model$/m)
        );

        // Check 11.2: AAA Login Authentication
        const aaaAuthLoginDefaultCheck = configContent.match(/aaa authentication login default/i);
        let unconfiguredLoginLines = [];
        if (!aaaAuthLoginDefaultCheck) {
            const lineRegex = /line (vty|con) (\d+(?: \d+)?)\s*([\s\S]*?)(?=\nline|\n!|$)/gi;
            let lineMatch;
            while ((lineMatch = lineRegex.exec(configContent)) !== null) {
                const lineName = `line ${lineMatch[1]} ${lineMatch[2]}`;
                const lineConfig = lineMatch[3];
                if (!lineConfig.includes("login authentication") && !lineConfig.includes("no login")) {
                    unconfiguredLoginLines.push(lineName);
                }
            }
        }
        if (unconfiguredLoginLines.length > 0) {
            createFinding('check-11.2', 'CIS 1.3.2', "Configurar Autenticación AAA para Login", Severity.MEDIUM, FindingStatus.NON_COMPLIANT,
                `No se encontró una lista de autenticación por defecto ('default') y las siguientes líneas no tienen un método de autenticación AAA explícito aplicado: ${unconfiguredLoginLines.join(', ')}.`,
                "Se recomienda definir una lista de autenticación por defecto o aplicar una lista nombrada a cada línea.\n\nEjemplo (Default):\nconfigure terminal\n aaa authentication login default group tacacs+ local\nend\n\nEjemplo (Nombrada):\nconfigure terminal\n line vty 0 4\n  login authentication MI_LISTA_AAA\nend",
                unconfiguredLoginLines,
                "No asegurar todas las líneas de acceso con un método de autenticación AAA deja vectores de entrada desprotegidos."
            );
        } else {
            createFinding('check-11.2', 'CIS 1.3.2', "Autenticación AAA para Login Configurada", Severity.MEDIUM, FindingStatus.COMPLIANT,
                "Se ha configurado una lista de autenticación de login por defecto, o todas las líneas tienen métodos de autenticación explícitos.",
                "Verifique que los métodos aplicados (ej. 'group tacacs+', 'local') sean los deseados y estén correctamente configurados.",
                 configContent.match(/^aaa authentication login default.*$/m)
            );
        }

        // Check 11.3: AAA Exec Authorization
        const aaaAuthzExecDefaultCheck = configContent.match(/aaa authorization exec default/i);
        let unconfiguredAuthzLines = [];
        if (!aaaAuthzExecDefaultCheck) {
            const lineRegex = /line (vty|con) (\d+(?: \d+)?)\s*([\s\S]*?)(?=\nline|\n!|$)/gi;
            let lineMatch;
            while ((lineMatch = lineRegex.exec(configContent)) !== null) {
                const lineName = `line ${lineMatch[1]} ${lineMatch[2]}`;
                const lineConfig = lineMatch[3];
                if (!lineConfig.includes("authorization exec")) {
                    unconfiguredAuthzLines.push(lineName);
                }
            }
        }
        if (unconfiguredAuthzLines.length > 0) {
            createFinding('check-11.3', 'CIS 1.3.4', "Configurar Autorización AAA para Exec", Severity.MEDIUM, FindingStatus.NON_COMPLIANT,
                `No se encontró una lista de autorización EXEC por defecto ('default') y las siguientes líneas no tienen un método de autorización explícito aplicado: ${unconfiguredAuthzLines.join(', ')}.`,
                "Defina una lista de autorización por defecto o aplique una a cada línea relevante.\n\nEjemplo (Default):\nconfigure terminal\n aaa authorization exec default group tacacs+ local if-authenticated\nend",
                unconfiguredAuthzLines,
                "Sin autorización EXEC, los usuarios que inician sesión pueden obtener acceso de shell sin los controles de privilegios adecuados."
            );
        } else {
            createFinding('check-11.3', 'CIS 1.3.4', "Autorización AAA para Exec Configurada", Severity.MEDIUM, FindingStatus.COMPLIANT,
                "Se ha configurado una lista de autorización EXEC por defecto, o todas las líneas relevantes tienen métodos de autorización explícitos.",
                "Verifique que los métodos de autorización sean los deseados.",
                configContent.match(/^aaa authorization exec default.*$/m)
            );
        }
    }

    if (osType === 'NX-OS') {
        const privilegedUsersRegex = /^username\s+\S+\s+.*role\s+network-admin.*$/gim;
        const privilegedUsers = configContent.match(privilegedUsersRegex) || [];
        if (privilegedUsers.length > 1) {
            createFinding('check-11.4-nxos', 'CIS 1.3 / Best Practice', 'Múltiples Usuarios con Rol "network-admin"', Severity.HIGH, FindingStatus.NON_COMPLIANT,
                `Se encontraron ${privilegedUsers.length} cuentas con el rol 'network-admin', que otorga privilegios completos.`,
                "Reduzca el número de cuentas con el rol 'network-admin' al mínimo absoluto. Utilice roles personalizados con privilegios limitados para las tareas diarias.",
                privilegedUsers,
                "En NX-OS, el rol 'network-admin' es el equivalente a root. Limitarlo es crucial para aplicar el principio de privilegio mínimo."
            );
        } else {
            createFinding('check-11.4-nxos', 'CIS 1.3 / Best Practice', 'Gestión de Rol "network-admin" Adecuada', Severity.HIGH, FindingStatus.COMPLIANT,
                `Se encontró ${privilegedUsers.length} cuenta(s) con el rol 'network-admin', lo cual es una buena práctica.`,
                "Asegúrese de que la(s) cuenta(s) con el rol 'network-admin' estén debidamente protegidas.",
                privilegedUsers
            );
        }
    } else { // IOS
        const userPrivilegeRegex = /^username\s+\S+\s+privilege\s+15.*$/gim;
        const privilegedUsers = configContent.match(userPrivilegeRegex) || [];
        if (privilegedUsers.length > 1) {
            createFinding('check-11.4', 'CIS 1.3 / Best Practice', 'Múltiples Usuarios con Privilegio 15 Encontrados', Severity.HIGH, FindingStatus.NON_COMPLIANT,
                `Se encontraron ${privilegedUsers.length} cuentas de usuario con el nivel de privilegio 15. Esto aumenta la superficie de ataque y viola el principio de privilegio mínimo.`,
                "Reduzca el privilegio de las cuentas no esenciales a un nivel inferior (ej. privilege 1 o 5) y utilice autorización granular de AAA para otorgar comandos específicos. Mantenga solo una o un número muy limitado de cuentas de emergencia con privilegio 15.",
                privilegedUsers,
                "Tener múltiples cuentas con 'privilege 15' es como entregar llaves maestras ilimitadas. Si una se ve comprometida, el atacante obtiene control total. El principio de privilegio mínimo limita drásticamente el daño potencial de una brecha de seguridad."
            );
        } else {
            createFinding('check-11.4', 'CIS 1.3 / Best Practice', 'Gestión de Privilegios de Administrador Adecuada', Severity.HIGH, FindingStatus.COMPLIANT,
                `Se encontró ${privilegedUsers.length} cuenta(s) con privilegio 15, lo cual está en línea con las mejores prácticas.`,
                "Asegúrese de que la(s) cuenta(s) con privilegio 15 esté(n) debidamente protegida(s) con contraseñas fuertes y su uso sea monitoreado.",
                privilegedUsers
            );
        }
    }

    if (osType === 'NX-OS') {
        if (!configContent.includes("aaa authentication login error-enable")) {
             createFinding('check-aaa-lockout-nxos', 'CIS 1.4.1', 'Configurar Bloqueo por Fallos de Login (NX-OS)', Severity.MEDIUM, FindingStatus.NON_COMPLIANT,
                "No se ha configurado el bloqueo por intentos de login fallidos ('aaa authentication login error-enable'). Esto es clave para mitigar ataques de fuerza bruta.",
                "Habilite el bloqueo de cuentas tras intentos fallidos:\nconfigure terminal\n aaa authentication login error-enable\nend\nConsidere también configurar los parámetros de bloqueo con 'login-attempts' en la sección de SSH.",
                undefined,
                "Esta configuración habilita el mecanismo global de bloqueo de cuentas de AAA tras intentos fallidos, un control de seguridad esencial."
             );
        } else {
             createFinding('check-aaa-lockout-nxos', 'CIS 1.4.1', 'Bloqueo por Fallos de Login Habilitado (NX-OS)', Severity.MEDIUM, FindingStatus.COMPLIANT,
                "El bloqueo por fallos de login a nivel de AAA ('aaa authentication login error-enable') está correctamente configurado.",
                "Asegúrese de que los parámetros de bloqueo (intentos, duración) estén definidos según su política de seguridad.",
                configContent.match(/^aaa authentication login error-enable$/m)
             );
        }
    }


    addFinding(findings);
};