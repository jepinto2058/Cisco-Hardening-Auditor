import { Severity, FindingStatus } from '../constants.js';

export const checkPasswords = (configContent, addFinding, osType) => {
    const findings = [];
    const createFinding = (id, cis, title, severity, status, description, recommendation, affectedLines, geminiExplanation) => {
        findings.push({ id, cisBenchmark: cis, title, severity, status, description, recommendation, affectedLines, geminiExplanation });
    };

    // --- Password Encryption ---
    if (!configContent.includes("service password-encryption")) {
        createFinding('check-1', 'CIS 1.1.1', 'Habilitar Ofuscación de Contraseñas', Severity.MEDIUM, FindingStatus.NON_COMPLIANT, "'service password-encryption' ofusca las contraseñas. Aunque no es un cifrado fuerte, previene la observación casual.", "Habilitar:\nconfigure terminal\n service password-encryption\nend", undefined, "No habilitarlo deja contraseñas en texto plano si la configuración es expuesta.");
    } else {
        createFinding('check-1', 'CIS 1.1.1', 'Ofuscación de Contraseñas Habilitada', Severity.MEDIUM, FindingStatus.COMPLIANT, "'service password-encryption' está habilitado.", "No se requiere acción.", configContent.match(/^service password-encryption$/m));
    }

    // --- Enable Secret/Password (IOS specific) ---
    if (osType === 'IOS') {
        const enableSecretRegex = /enable secret (0|5|8|9|\d+) (.+)/i;
        const enableSecretMatch = configContent.match(enableSecretRegex);
        const enablePasswordMatch = configContent.match(/enable password/i);

        if (enablePasswordMatch && !enableSecretMatch) {
            createFinding('check-2', 'CIS 1.2.1', "Usar 'enable secret' en lugar de 'enable password'", Severity.CRITICAL, FindingStatus.NON_COMPLIANT, "Se encontró 'enable password'. Se debe usar 'enable secret' ya que utiliza un hash más fuerte.", "Reemplazar 'enable password' con 'enable secret':\nconfigure terminal\n no enable password\n enable secret <SU_CONTRASEÑA_FUERTE>\nend", configContent.match(/enable password .+/gi));
        } else if (enableSecretMatch) {
            const secretType = enableSecretMatch[1];
            if (secretType === "5") {
                createFinding('check-2.2', 'CIS 1.2.1', "Considerar 'enable secret' con algoritmo más fuerte que MD5", Severity.MEDIUM, FindingStatus.NON_COMPLIANT, "'enable secret 5' usa MD5, que es susceptible a ataques. Si el IOS lo soporta, use SHA-256 (tipo 8) o Scrypt (tipo 9).", "Mejorar el algoritmo:\nconfigure terminal\n enable algorithm-type sha256 secret <SU_CONTRASEÑA_FUERTE>\nend", configContent.match(/enable secret 5 .+/gi));
            } else {
                 createFinding('check-2.3', 'CIS 1.2.1', "'enable secret' Configurado con Algoritmo Fuerte", Severity.CRITICAL, FindingStatus.COMPLIANT, `'enable secret' está configurado con un tipo de algoritmo moderno (Tipo ${secretType}).`, "No se requiere acción si la contraseña es robusta.", [enableSecretMatch[0]]);
            }
        } else {
            createFinding('check-2.5', 'CIS 1.2.1', "Configurar 'enable secret'", Severity.CRITICAL, FindingStatus.NON_COMPLIANT, "No se encontró 'enable secret'. Es crucial para proteger el acceso privilegiado.", "Configurar 'enable secret':\nconfigure terminal\n enable secret <SU_CONTRASEÑA_FUERTE>\nend");
        }
    } else { // NX-OS
         createFinding('check-2', 'CIS 1.2.1', "Uso de 'enable secret' no aplicable en NX-OS", Severity.CRITICAL, FindingStatus.NOT_APPLICABLE, "NX-OS no utiliza 'enable secret'. La seguridad del acceso privilegiado se gestiona a través de cuentas de usuario y roles.", "Asegúrese de que las cuentas de usuario con roles administrativos ('network-admin') tengan contraseñas fuertes y seguras.", undefined);
    }


    // --- Password Min Length ---
    const minLengthMatch = configContent.match(/security passwords min-length (\d+)/i);
    if (!minLengthMatch) {
        createFinding('check-12', 'CIS 1.2.2', 'Establecer Longitud Mínima de Contraseña', Severity.MEDIUM, FindingStatus.NON_COMPLIANT, "No se configuró 'security passwords min-length'.", "Establecer una longitud mínima de contraseña (ej. 14):\nconfigure terminal\n security passwords min-length 14\nend", undefined, "Forzar una longitud mínima aumenta la resistencia a ataques de fuerza bruta.");
    } else if (parseInt(minLengthMatch[1]) < 14) {
        createFinding('check-12', 'CIS 1.2.2', 'Aumentar Longitud Mínima de Contraseña', Severity.MEDIUM, FindingStatus.NON_COMPLIANT, `La longitud mínima es ${minLengthMatch[1]}, menor a la recomendada (14).`, `Aumentar la longitud:\nconfigure terminal\n security passwords min-length 14\nend`, [minLengthMatch[0]]);
    } else {
        createFinding('check-12', 'CIS 1.2.2', 'Longitud Mínima de Contraseña Adecuada', Severity.MEDIUM, FindingStatus.COMPLIANT, `Longitud mínima de contraseña establecida en ${minLengthMatch[1]}.`, "No se requiere acción.", [minLengthMatch[0]]);
    }
    
    // --- Login Lockout (IOS specific) ---
    if (osType === 'IOS') {
        if (!configContent.includes("login block-for")) {
            createFinding('check-25', 'CIS 1.4.1', 'Configurar Bloqueo de Intentos de Login Fallidos', Severity.MEDIUM, FindingStatus.NON_COMPLIANT, "No se ha configurado el bloqueo por intentos de login fallidos.", "Habilitar el bloqueo:\nconfigure terminal\n login block-for 120 attempts 3 within 60\nend", undefined, "Esta configuración protege contra ataques de fuerza bruta a las credenciales.");
        } else {
            createFinding('check-25', 'CIS 1.4.1', 'Bloqueo de Intentos de Login Fallidos Configurado', Severity.MEDIUM, FindingStatus.COMPLIANT, "El bloqueo por intentos de login fallidos ('login block-for') está configurado.", "Verifique que los parámetros sean adecuados para su política de seguridad.", configContent.match(/^login block-for.*$/m));
        }
    }


    addFinding(findings);
};