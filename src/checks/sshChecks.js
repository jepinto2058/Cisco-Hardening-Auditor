
import { Severity, FindingStatus } from '../constants.js';

export const checkSsh = (configContent, addFinding, osType) => {
    const findings = [];
    const createFinding = (id, cis, title, severity, status, description, recommendation, affectedLines, geminiExplanation) => {
        findings.push({ id, cisBenchmark: cis, title, severity, status, description, recommendation, affectedLines, geminiExplanation });
    };

    // A reliable check for active SSH is the presence of 'ip ssh' commands or 'transport input ssh'
    const sshIsActive = configContent.match(/ip ssh/i) || configContent.match(/transport input ssh/i) || configContent.match(/^ssh key/m);

    // --- SSH Version ---
    if (configContent.match(/ip ssh version 1/i)) {
        createFinding('check-13.1', 'CIS 5.3.1', 'Usar SSH Versión 2', Severity.HIGH, FindingStatus.NON_COMPLIANT, "SSH Versión 1 está explícitamente configurada. SSHv1 tiene vulnerabilidades conocidas y no debe usarse.", "Forzar SSH Versión 2:\nconfigure terminal\n ip ssh version 2\nend", configContent.match(/ip ssh version 1/ig));
    } else if (sshIsActive && configContent.match(/ip ssh version 2/i)) {
        createFinding('check-13.1', 'CIS 5.3.1', 'SSH Versión 2 Configurada', Severity.HIGH, FindingStatus.COMPLIANT, "SSH está configurado para usar solo la Versión 2, lo cual es la mejor práctica de seguridad.", "No se requiere acción.", configContent.match(/ip ssh version 2/ig));
    } else if (sshIsActive && !configContent.match(/ip ssh version/i)) {
        createFinding('check-13.1', 'CIS 5.3.1', 'Especificar SSH Versión 2', Severity.HIGH, FindingStatus.NON_COMPLIANT, "SSH parece habilitado, pero la versión no está forzada a 2. Dependiendo del IOS, se podría permitir SSHv1 por defecto.", "Forzar SSH Versión 2 para mayor seguridad:\nconfigure terminal\n ip ssh version 2\nend", undefined, "Es una buena práctica forzar explícitamente SSHv2 para evitar el uso accidental de SSHv1.");
    } else if (!sshIsActive) {
         createFinding('check-13.1', 'CIS 5.3.1', 'SSH Parece Deshabilitado', Severity.INFORMATIONAL, FindingStatus.NOT_APPLICABLE, "No se encontraron configuraciones que indiquen que SSH está activo.", "Si se requiere SSH, asegúrese de generar claves RSA, configurar 'ip ssh version 2' y habilitarlo con 'transport input ssh' en las líneas VTY.");
    }

    if (!sshIsActive) {
        addFinding(findings);
        return; // Don't run other SSH checks if it's not active
    }
    
    // --- SSH RSA Key Size ---
    const rsaKeyGenRegex = /crypto key generate rsa.*modulus (\d+)/i;
    const rsaKeyGenMatch = configContent.match(rsaKeyGenRegex);
    const nxosRsaKeyRegex = /ssh key rsa (\d+)/;
    const nxosRsaKeyMatch = configContent.match(nxosRsaKeyRegex);

    let keySizeFound = null;
    let keyLine = null;

    if (rsaKeyGenMatch) {
        keySizeFound = parseInt(rsaKeyGenMatch[1]);
        keyLine = rsaKeyGenMatch[0];
    } else if (nxosRsaKeyMatch) {
        keySizeFound = parseInt(nxosRsaKeyMatch[1]);
        keyLine = nxosRsaKeyMatch[0];
    }

    if (keySizeFound !== null) {
        if (keySizeFound < 2048) {
            createFinding('check-ssh-keysize', 'CIS 5.3.0', 'Tamaño de Clave RSA para SSH es Débil', Severity.HIGH, FindingStatus.NON_COMPLIANT, `El tamaño de la clave RSA es ${keySizeFound}, que es menor al mínimo recomendado de 2048 bits.`, "Genere una nueva clave RSA con un tamaño de módulo de al menos 2048 bits:\nconfigure terminal\n crypto key generate rsa modulus 2048\nend", [keyLine], "Claves más cortas son susceptibles a ataques de fuerza bruta con la computación moderna.");
        } else {
            createFinding('check-ssh-keysize', 'CIS 5.3.0', 'Tamaño de Clave RSA para SSH es Fuerte', Severity.HIGH, FindingStatus.COMPLIANT, `El tamaño de la clave RSA es ${keySizeFound}, lo cual cumple con las recomendaciones actuales.`, "No se requiere acción.", [keyLine]);
        }
    } else {
         createFinding('check-ssh-keysize', 'CIS 5.3.0', 'No se pudo determinar el tamaño de la clave RSA', Severity.MEDIUM, FindingStatus.NON_COMPLIANT, "No se encontró un comando de generación de clave RSA ('crypto key generate' o 'ssh key') que especifique su tamaño. SSH requiere una clave RSA para operar y su fortaleza es crítica.", "Asegúrese de que se haya generado una clave RSA con un tamaño de módulo de al menos 2048 bits en el dispositivo.", undefined, "La clave RSA es la base de la identidad del servidor SSH. Una clave débil compromete toda la sesión.");
    }


    // --- SSH Time-out and Retries ---
    const sshTimeoutMatch = configContent.match(/ip ssh time-out (\d+)/i);
    if (!sshTimeoutMatch) {
        createFinding('check-13.2', 'CIS 5.3.2', 'Configurar Timeout para SSH', Severity.LOW, FindingStatus.NON_COMPLIANT, "No se configuró un timeout para las sesiones SSH, dejándolas abiertas indefinidamente.", "Establecer un timeout (ej. 600 segundos/10 minutos):\nconfigure terminal\n ip ssh time-out 600\nend");
    } else if (parseInt(sshTimeoutMatch[1]) > 900) {
        createFinding('check-13.2', 'CIS 5.3.2', 'Timeout SSH Podría ser Demasiado Largo', Severity.LOW, FindingStatus.NON_COMPLIANT, `El timeout SSH es ${sshTimeoutMatch[1]} segundos (> 15 min). Considere un valor más corto para cerrar sesiones inactivas antes.`, `Ajustar el timeout:\nconfigure terminal\n ip ssh time-out 600\nend`, [sshTimeoutMatch[0]]);
    }
    
    if (osType === 'NX-OS') {
        const nxosRetriesMatch = configContent.match(/^ssh login-attempts (\d+)/im);
        if (!nxosRetriesMatch) {
            createFinding('check-13.3-nxos', 'CIS 5.3.3', 'Configurar Límite de Intentos de Login SSH (NX-OS)', Severity.MEDIUM, FindingStatus.NON_COMPLIANT, "No se limitó el número de intentos de login SSH ('ssh login-attempts').", "Establezca un número bajo de intentos (ej. 3):\nconfigure terminal\n ssh login-attempts 3\nend", undefined);
        } else if (parseInt(nxosRetriesMatch[1]) > 3) {
            createFinding('check-13.3-nxos', 'CIS 5.3.3', 'Número de Intentos de Login SSH Muy Alto (NX-OS)', Severity.MEDIUM, FindingStatus.NON_COMPLIANT, `El número de intentos SSH es ${nxosRetriesMatch[1]}. Se recomienda 3 o menos.`, `Reducir los intentos:\nconfigure terminal\n ssh login-attempts 3\nend`, [nxosRetriesMatch[0]]);
        }
    } else { // IOS
        const sshAuthRetriesMatch = configContent.match(/ip ssh authentication-retries (\d+)/i);
        if (!sshAuthRetriesMatch) {
            createFinding('check-13.3', 'CIS 5.3.3', 'Configurar Reintentos de Autenticación SSH', Severity.MEDIUM, FindingStatus.NON_COMPLIANT, "No se limitó el número de reintentos de autenticación SSH, facilitando ataques de fuerza bruta.", "Establecer un número bajo de reintentos (ej. 3):\nconfigure terminal\n ip ssh authentication-retries 3\nend");
        } else if (parseInt(sshAuthRetriesMatch[1]) > 3) {
            createFinding('check-13.3', 'CIS 5.3.3', 'Número de Reintentos SSH Muy Alto', Severity.MEDIUM, FindingStatus.NON_COMPLIANT, `El número de reintentos SSH es ${sshAuthRetriesMatch[1]}. Un valor alto facilita ataques de fuerza bruta. Se recomienda 3 o menos.`, `Reducir los reintentos:\nconfigure terminal\n ip ssh authentication-retries 3\nend`, [sshAuthRetriesMatch[0]]);
        }
    }


    // --- SSH Algorithm Checks ---
    const checkAlgorithm = (configLineRegex, weakList, findingInfo) => {
        const match = configContent.match(configLineRegex);
        
        if (match) {
            const configuredAlgs = match[1].split(' ').filter(alg => alg.trim() !== '');
            const foundWeakAlgs = configuredAlgs.filter(alg => weakList.includes(alg));
            const foundStrongAlgs = configuredAlgs.filter(alg => !weakList.includes(alg));

            if (foundWeakAlgs.length > 0) {
                createFinding(
                    findingInfo.idWeak, 
                    findingInfo.cis, 
                    `Algoritmos ${findingInfo.name} Débiles Permitidos`, 
                    Severity.MEDIUM, 
                    FindingStatus.NON_COMPLIANT, 
                    `La configuración SSH permite los siguientes algoritmos ${findingInfo.name} débiles: ${foundWeakAlgs.join(', ')}. Estos algoritmos tienen vulnerabilidades conocidas o debilidades teóricas.`,
                    `Elimine los algoritmos débiles de la configuración. Ejemplo de configuración segura:\n${findingInfo.recommendation}`, 
                    [match[0]], 
                    findingInfo.explanation
                );
            }

            if (foundStrongAlgs.length > 0) {
                createFinding(
                    findingInfo.idStrong, 
                    findingInfo.cis, 
                    `Algoritmos ${findingInfo.name} Fuertes Configurados`, 
                    Severity.INFORMATIONAL, 
                    FindingStatus.COMPLIANT, 
                    `La configuración SSH utiliza los siguientes algoritmos ${findingInfo.name} fuertes, lo cual es una buena práctica: ${foundStrongAlgs.join(', ')}.`,
                    "No se requiere acción para estos algoritmos. Continúe utilizando algoritmos criptográficos modernos y fuertes.",
                    [match[0]]
                );
            }
        } else {
            createFinding(
                findingInfo.idDefault, 
                findingInfo.cis, 
                `Configuración de Algoritmos ${findingInfo.name} de SSH no Explícita`, 
                Severity.LOW, 
                FindingStatus.NON_COMPLIANT, 
                `No se especificaron explícitamente los algoritmos ${findingInfo.name}. El dispositivo usará los valores por defecto, que pueden incluir algoritmos débiles y obsoletos.`, 
                `Configure explícitamente una lista de algoritmos ${findingInfo.name} fuertes. Ejemplo:\n${findingInfo.recommendation}`, 
                undefined, 
                'Dejar los valores por defecto es arriesgado, ya que las versiones de IOS más antiguas pueden incluir cifrados débiles. Especificar explícitamente los algoritmos garantiza una postura de seguridad fuerte y consistente.'
            );
        }
    };

    checkAlgorithm(
        /ip ssh server algorithm mac (.*)/i,
        ['hmac-sha1', 'hmac-sha1-96', 'hmac-md5'],
        {
            idWeak: 'check-ssh-mac-weak',
            idStrong: 'check-ssh-mac-strong',
            idDefault: 'check-ssh-mac-default',
            cis: 'CIS 5.3.6',
            name: 'MAC',
            recommendation: 'configure terminal\n ip ssh server algorithm mac hmac-sha2-512 hmac-sha2-256\nend',
            explanation: 'HMAC-SHA1 es teóricamente más débil y susceptible a ataques de colisión en comparación con los algoritmos basados en SHA-2.'
        }
    );

    checkAlgorithm(
        /ip ssh server algorithm kex (.*)/i,
        ['diffie-hellman-group1-sha1', 'diffie-hellman-group14-sha1'],
        {
            idWeak: 'check-ssh-kex-weak',
            idStrong: 'check-ssh-kex-strong',
            idDefault: 'check-ssh-kex-default',
            cis: 'CIS 5.3.6',
            name: 'de Intercambio de Claves (KEX)',
            recommendation: 'configure terminal\n ip ssh server algorithm kex diffie-hellman-group-exchange-sha256 ecdh-sha2-nistp384\nend',
            explanation: 'Los algoritmos de intercambio de claves basados en SHA1 se consideran obsoletos y son vulnerables. Utilice grupos Diffie-Hellman más fuertes y basados en SHA-2.'
        }
    );
    
    checkAlgorithm(
        /ip ssh server algorithm encryption (.*)/i,
        ['aes128-cbc', '3des-cbc', 'aes192-cbc', 'aes256-cbc'],
        {
            idWeak: 'check-ssh-encryption-weak',
            idStrong: 'check-ssh-encryption-strong',
            idDefault: 'check-ssh-encryption-default',
            cis: 'CIS 5.3.6',
            name: 'de Cifrado',
            recommendation: 'configure terminal\n ip ssh server algorithm encryption aes256-ctr aes192-ctr aes128-ctr\nend',
            explanation: 'Los cifrados en modo CBC son susceptibles a ataques de "padding oracle" (como el ataque POODLE). Se deben usar modos de cifrado modernos y autenticados como CTR o GCM para mitigar este riesgo.'
        }
    );

    addFinding(findings);
};