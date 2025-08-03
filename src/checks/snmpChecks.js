import { Severity, FindingStatus } from '../constants.js';

export const checkSnmp = (configContent, addFinding, osType) => {
    const findings = [];
    const createFinding = (id, cis, title, severity, status, description, recommendation, affectedLines, geminiExplanation) => {
        findings.push({ id, cisBenchmark: cis, title, severity, status, description, recommendation, affectedLines, geminiExplanation });
    };
    
    // --- SNMPv1/v2c Community Checks ---
    const snmpCommunityRegex = /snmp-server community (\S+) (RO|RW)(?: (\S+))?/gi;
    let snmpMatch;
    let snmpCommunitiesFound = false;
    const communitiesWithoutAcl = [];
    const communitiesWithAcl = [];

    while((snmpMatch = snmpCommunityRegex.exec(configContent)) !== null) {
        snmpCommunitiesFound = true;
        const communityLine = snmpMatch[0];
        const communityName = snmpMatch[1];
        const accessType = snmpMatch[2];
        const aclName = snmpMatch[3];

        if (communityName === "public" || communityName === "private") {
            createFinding(`check-10.1-${communityName}`, 'CIS 3.4.2', `SNMP usa Comunidad por Defecto '${communityName}'`, Severity.HIGH, FindingStatus.NON_COMPLIANT, `Se está utilizando la comunidad SNMP por defecto '${communityName}'. Estas son bien conocidas y deben cambiarse.`, `Cambiar la comunidad SNMP y aplicar una ACL:\nconfigure terminal\n no snmp-server community ${communityName}\n snmp-server community <NUEVA_COMUNIDAD> ${accessType} <NOMBRE_ACL>\nend`, [communityLine]);
        } else if (!aclName) {
            communitiesWithoutAcl.push(communityLine);
        } else {
            communitiesWithAcl.push(communityLine);
        }
    }
    
    if(communitiesWithoutAcl.length > 0) {
        createFinding('check-10.2-grouped', 'CIS 3.4.3', 'Comunidades SNMP no Protegidas por ACL', Severity.MEDIUM, FindingStatus.NON_COMPLIANT, 
        `Se encontraron ${communitiesWithoutAcl.length} comunidades SNMP que no están protegidas por una lista de control de acceso (ACL).`, 
        `Aplique una ACL a cada comunidad SNMP para restringir el acceso solo a los servidores de gestión de red (NMS) autorizados.\n\nEjemplo:\nconfigure terminal\n ip access-list standard SNMP_NMS_ACL\n  permit host <IP_NMS_1>\n  deny any log\nend\n\n snmp-server community <NOMBRE_COMUNIDAD> RO SNMP_NMS_ACL`,
        communitiesWithoutAcl);
    }

    if (communitiesWithAcl.length > 0) {
        createFinding('check-10.3-grouped', 'CIS 3.4.3', 'Comunidades SNMP Protegidas por ACL', Severity.MEDIUM, FindingStatus.COMPLIANT,
        `Se encontraron ${communitiesWithAcl.length} comunidades SNMP correctamente protegidas por una lista de control de acceso.`,
        "Verifique que las ACLs aplicadas restrinjan el acceso únicamente a los servidores NMS autorizados y necesarios.",
        communitiesWithAcl);
    }

    // --- SNMPv3 Checks ---
    const snmpv3UserRegex = /snmp-server user (\S+).* (priv)/gi;
    const snmpv3Users = configContent.match(snmpv3UserRegex);
    if (snmpv3Users && snmpv3Users.length > 0) {
        createFinding('check-snmp-v3', 'CIS 3.4.1', 'Uso de SNMPv3 con Privacidad (priv)', Severity.HIGH, FindingStatus.COMPLIANT,
            `Se detectó el uso de SNMPv3 con ${snmpv3Users.length} usuario(s) configurado(s) para 'priv' (autenticación y cifrado), lo cual es la mejor práctica de seguridad.`,
            "Asegúrese de que las contraseñas de autenticación y privacidad sean fuertes y se gestionen de forma segura.",
            snmpv3Users,
            "SNMPv3 con 'priv' proporciona autenticación para verificar la fuente y cifrado para proteger la confidencialidad de los datos, a diferencia de las versiones v1/v2c que envían todo en texto claro."
        );
    }

    // --- Overall SNMP Status ---
    if (!snmpCommunitiesFound && !snmpv3Users) {
        if (configContent.includes("snmp-server")) {
            createFinding('check-10.4', 'CIS 3.4', 'Configuración SNMP Incompleta', Severity.MEDIUM, FindingStatus.NON_COMPLIANT, "Existen comandos 'snmp-server' pero no se definieron comunidades v1/v2c ni usuarios v3. La configuración de SNMP es incompleta o podría estar usando solo trampas.", "Si se requiere SNMP, configure SNMPv3 con autenticación y privacidad para una seguridad robusta.");
        } else {
            createFinding('check-10.5', 'CIS 3.4', 'SNMP Parece Deshabilitado', Severity.LOW, FindingStatus.COMPLIANT, "No se encontraron configuraciones de 'snmp-server'.", "No se requiere acción si SNMP no es necesario.");
        }
    }
    
    addFinding(findings);
};