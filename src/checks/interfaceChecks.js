

import { Severity, FindingStatus } from '../constants.js';

export const checkInterfaces = (configContent, addFinding, osType) => {
    const findings = [];
    const createFinding = (id, cis, title, severity, status, description, recommendation, affectedLines, geminiExplanation) => {
        findings.push({ id, cisBenchmark: cis, title, severity, status, description, recommendation, affectedLines, geminiExplanation });
    };

    const interfaceRegex = /interface ([\w\d\/\-\.]+)\s*([\s\S]*?)(?=\ninterface|\n!|$)/gi;
    let match;
    const interfaceSections = [];
    while((match = interfaceRegex.exec(configContent)) !== null) {
        interfaceSections.push({name: match[1], config: match[2], raw: match[0]});
    }

    // --- CDP Global Check ---
    const noCdpRunGlobal = configContent.includes("no cdp run");
    const cdpRunGlobal = configContent.includes("cdp run");
    if (!noCdpRunGlobal && cdpRunGlobal) {
        createFinding('check-9.1', 'CIS 5.2.1', 'Considerar Deshabilitar CDP Globalmente si no es Necesario', Severity.LOW, FindingStatus.NON_COMPLIANT, "CDP ('cdp run') está habilitado globalmente. Deshabilítelo si no es estrictamente necesario para evitar la fuga de información de topología.", "Si CDP no es necesario:\nconfigure terminal\n no cdp run\nend", configContent.match(/cdp run/gi));
    } else if (noCdpRunGlobal) {
        createFinding('check-9.1', 'CIS 5.2.1', 'CDP Deshabilitado Globalmente', Severity.LOW, FindingStatus.COMPLIANT, "CDP está deshabilitado globalmente.", "No se requiere acción.", configContent.match(/^no cdp run$/m));
    }

    // --- Interface-specific checks ---
    let unusedInterfacesFromBrief = [];
    const showIpIntBriefRegex = /Interface\s+IP-Address\s+OK\?\s+Method\s+Status\s+Protocol\s*([\s\S]*)/i;
    const showIpIntBriefMatch = configContent.match(showIpIntBriefRegex);
    if (showIpIntBriefMatch) {
          const briefContent = showIpIntBriefMatch[1];
          const lineRegex = /^([\w\d\/\.-]+)\s+.*? (?:administratively )?(down)\s+(down)\s*$/gm;
          let briefMatch;
          while ((briefMatch = lineRegex.exec(briefContent)) !== null) {
              if (!/Vlan|Loopback|Port-channel/i.test(briefMatch[1])) {
                  unusedInterfacesFromBrief.push(briefMatch[1]);
              }
          }
    }

    const portSecurityNonCompliantInterfaces = [];
    const portSecurityCompliantInterfaces = [];
    const trunksWithoutPruning = [];
    const trunksWithPruning = [];
    const cdpEnabledInterfaces = [];
    const cdpDisabledInterfaces = [];
    const interfacesWithoutDescription = [];
    const interfacesWithDescription = [];
    const nxosEdgePorts = [];
    const nxosNetworkPorts = [];
    const nxosNeitherEdgeNetwork = [];


    for (const iface of interfaceSections) {
        const isSwitchPort = iface.config.includes("switchport");
        
        // Group CDP on Interfaces
        if (!noCdpRunGlobal && !/Loopback|Vlan1/i.test(iface.name)) {
            if (iface.config.includes("no cdp enable")) {
                cdpDisabledInterfaces.push(iface.name);
            } else {
                cdpEnabledInterfaces.push(iface.name);
            }
        }
        
        // --- Spanning Tree and Layer 2 Checks (if switchport) ---
        if(isSwitchPort) {
            if (iface.config.includes("switchport mode access") && (!iface.config.match(/switchport access vlan (\d+)/i) || (iface.config.match(/switchport access vlan (\d+)/i)[1] === '1')) && !iface.config.includes("shutdown")) {
                createFinding(`check-23-${iface.name}`, 'CIS L2.4', `Puerto de Acceso en VLAN 1 por Defecto: ${iface.name}`, Severity.LOW, FindingStatus.NON_COMPLIANT, `El puerto de acceso ${iface.name} está en la VLAN 1 por defecto. Se recomienda no usar la VLAN 1 para tráfico de usuario.`, `Mueva el puerto a una VLAN de acceso específica:\ninterface ${iface.name}\n switchport access vlan <NUEVA_VLAN>\nend`, [iface.raw.split('\n')[0]]);
            }
            // Group Port Security checks
            if (iface.config.includes("switchport mode access") && !iface.config.includes("shutdown")) {
                if (iface.config.includes("switchport port-security")) {
                    portSecurityCompliantInterfaces.push(iface.name);
                } else {
                    portSecurityNonCompliantInterfaces.push(iface.name);
                }
            }
            // Group VLAN Pruning checks
            if (iface.config.includes("switchport mode trunk")) {
                if (!iface.config.includes("switchport trunk allowed vlan")) {
                    trunksWithoutPruning.push(iface.name);
                } else {
                    trunksWithPruning.push(iface.name);
                }
            }

             // NX-OS Specific Spanning Tree Port Type
            if (osType === 'NX-OS' && !/port-channel\d+/.test(iface.name)) {
                if (iface.config.includes("spanning-tree port type edge")) {
                    nxosEdgePorts.push(iface.name);
                } else if (iface.config.includes("spanning-tree port type network")) {
                    nxosNetworkPorts.push(iface.name);
                } else {
                    nxosNeitherEdgeNetwork.push(iface.name);
                }
            }
        }
        
        // Group Interface Description checks
        if (!/vlan1|loopback/i.test(iface.name)) {
             if (iface.config.includes("description ")) {
                interfacesWithDescription.push(iface.name);
            } else {
                interfacesWithoutDescription.push(iface.name);
            }
        }
    }
    
    // Grouped Port Security Findings
    if (portSecurityNonCompliantInterfaces.length > 0) {
        createFinding(
            'check-28-grouped',
            'CIS L2.5',
            'Port Security no Habilitado en Puertos de Acceso',
            Severity.MEDIUM,
            FindingStatus.NON_COMPLIANT,
            `Se encontraron ${portSecurityNonCompliantInterfaces.length} puertos de acceso que no tienen Port Security habilitado, permitiendo que cualquier dispositivo se conecte.`,
            `Habilite Port Security en todas las interfaces de acceso para controlar qué dispositivos pueden conectarse a la red. Ejemplo para una interfaz:\ninterface <nombre_interfaz>\n switchport port-security\n switchport port-security maximum 2\n switchport port-security violation restrict\n switchport port-security mac-address sticky\nend`,
            portSecurityNonCompliantInterfaces.map(iface => `interface ${iface}`),
            "Port Security es una defensa de capa 2 fundamental. Limita el número de direcciones MAC permitidas en un puerto, evitando que los atacantes conecten múltiples dispositivos o suplanten MACs para acceder a la red."
        );
    }
    if (portSecurityCompliantInterfaces.length > 0) {
        createFinding(
            'check-28-compliant-grouped',
            'CIS L2.5',
            'Port Security Habilitado en Puertos de Acceso',
            Severity.MEDIUM,
            FindingStatus.COMPLIANT,
            `Se encontraron ${portSecurityCompliantInterfaces.length} puertos de acceso con Port Security correctamente habilitado.`,
            "Verifique que la configuración de Port Security (maximum, violation, etc.) en cada puerto cumpla con las políticas de seguridad de su organización.",
            portSecurityCompliantInterfaces.map(iface => `interface ${iface}`)
        );
    }

    // Grouped VLAN Pruning Findings
    if (trunksWithoutPruning.length > 0) {
        createFinding(
            'check-prune-grouped-noncompliant',
            'CIS L2.6',
            'Falta de Pruning de VLANs en Puertos Troncales',
            Severity.MEDIUM,
            FindingStatus.NON_COMPLIANT,
            `Se encontraron ${trunksWithoutPruning.length} puertos troncales que permiten todas las VLANs por defecto, lo que puede exponer la red a riesgos como VLAN hopping.`,
            `Limite las VLANs permitidas en cada puerto troncal para minimizar la superficie de ataque. Ejemplo para una interfaz:\ninterface <nombre_interfaz>\n switchport trunk allowed vlan <lista_de_vlans_permitidas>\nend`,
            trunksWithoutPruning.map(iface => `interface ${iface}`),
            "No limitar las VLANs en un troncal (pruning) permite que el tráfico de todas las VLANs fluya a través de él, aumentando el riesgo de ataques de VLAN hopping y la exposición innecesaria de segmentos de red."
        );
    }
    if (trunksWithPruning.length > 0) {
        createFinding(
            'check-prune-grouped-compliant',
            'CIS L2.6',
            'Pruning de VLANs Configurado en Puertos Troncales',
            Severity.MEDIUM,
            FindingStatus.COMPLIANT,
            `Se encontraron ${trunksWithPruning.length} puertos troncales con una lista de VLANs permitidas configurada, lo cual es una buena práctica de seguridad.`,
            "Verifique que la lista de VLANs permitidas en cada puerto troncal sea la mínima necesaria para las operaciones de la red.",
            trunksWithPruning.map(iface => `interface ${iface}`)
        );
    }

    // Grouped CDP Findings
    if (cdpEnabledInterfaces.length > 0) {
        createFinding(
            'check-9.2-grouped-noncompliant',
            'CIS 5.2.2',
            'CDP Habilitado en Interfaces',
            Severity.LOW,
            FindingStatus.NON_COMPLIANT,
            `CDP está habilitado en ${cdpEnabledInterfaces.length} interfaz/ces. Considere deshabilitarlo en interfaces no confiables para evitar la fuga de información de topología.`,
            `Deshabilite CDP en las interfaces no confiables:\nconfigure terminal\n interface <nombre_interfaz>\n  no cdp enable\n end`,
            cdpEnabledInterfaces.map(iface => `interface ${iface}`),
            "Cisco Discovery Protocol (CDP) transmite información sobre el dispositivo a vecinos directamente conectados. Aunque es útil para la resolución de problemas, puede ser explotado por un atacante en un puerto no confiable para mapear la topología de la red."
        );
    }
    if (cdpDisabledInterfaces.length > 0) {
        createFinding(
            'check-9.2-grouped-compliant',
            'CIS 5.2.2',
            'CDP Deshabilitado Explícitamente en Interfaces',
            Severity.LOW,
            FindingStatus.COMPLIANT,
            `CDP se ha deshabilitado explícitamente en ${cdpDisabledInterfaces.length} interfaz/ces, lo cual es una buena práctica de seguridad.`,
            "No se requiere acción para estas interfaces.",
            cdpDisabledInterfaces.map(iface => `interface ${iface}`)
        );
    }
    
    // Grouped Description Findings
    if (interfacesWithoutDescription.length > 0) {
        createFinding(
            'check-desc-grouped-noncompliant',
            'Operational Best Practice',
            'Falta Descripción en Interfaces',
            Severity.LOW,
            FindingStatus.NON_COMPLIANT,
            `Se encontraron ${interfacesWithoutDescription.length} interfaces sin una descripción configurada, lo que dificulta la gestión y solución de problemas.`,
            `Añada una descripción a cada interfaz para identificar su propósito. Ejemplo:\ninterface <nombre_interfaz>\n description <Texto_descriptivo>\nend`,
            interfacesWithoutDescription.map(iface => `interface ${iface}`),
            "Las descripciones en las interfaces son vitales para la documentación de la red. Ayudan a los administradores a entender rápidamente la función de cada conexión, ahorrando tiempo durante incidentes o cambios."
        );
    }
    if (interfacesWithDescription.length > 0) {
        createFinding(
            'check-desc-grouped-compliant',
            'Operational Best Practice',
            'Descripciones Configuradas en Interfaces',
            Severity.LOW,
            FindingStatus.COMPLIANT,
            `Se encontraron ${interfacesWithDescription.length} interfaces con una descripción configurada, lo cual es una excelente práctica operativa.`,
            "Asegúrese de que las descripciones sean precisas y se mantengan actualizadas con cualquier cambio en la topología de la red.",
            interfacesWithDescription.map(iface => `interface ${iface}`)
        );
    }
    
    // Unused Interfaces Check (from brief or config)
    const unusedInterfaces = unusedInterfacesFromBrief.length > 0 ? unusedInterfacesFromBrief : interfaceSections.filter(iface => !/Vlan|Loopback|Port-channel/i.test(iface.name) && !iface.config.includes("shutdown")).map(iface => iface.name);
    if(unusedInterfaces.length > 0) {
        createFinding('check-29', 'CIS L2.3', 'Interfaces Físicas no Utilizadas Habilitadas', Severity.MEDIUM, FindingStatus.NON_COMPLIANT, `Se han identificado ${unusedInterfaces.length} interfaces físicas habilitadas pero sin uso aparente. Interfaces: ${unusedInterfaces.slice(0,5).join(', ')}${unusedInterfaces.length > 5 ? '...' : ''}.`, "Deshabilite administrativamente todas las interfaces no utilizadas con `shutdown` y asígnelas a una VLAN de 'agujero negro'.", unusedInterfaces.map(i => `interface ${i}`), "Dejar puertos habilitados pero sin conectar es como dejar una puerta sin cerradura. Cualquiera puede conectarse y obtener acceso a la red.");
    }
    
     const isSwitch = configContent.match(/spanning-tree mode/i) || configContent.match(/switchport mode/i);
     if (isSwitch) {
        const bpduGuardDefaultIOS = configContent.includes("spanning-tree portfast bpduguard default");
        const bpduGuardDefaultNXOS = configContent.includes("spanning-tree port type edge bpduguard default");
        if (!bpduGuardDefaultIOS && !bpduGuardDefaultNXOS) {
          createFinding('check-21', 'CIS L2.1', 'Habilitar BPDU Guard por Defecto', Severity.MEDIUM, FindingStatus.NON_COMPLIANT, "BPDU Guard previene bucles de spanning-tree al deshabilitar puertos PortFast/Edge si reciben BPDUs.", "Habilitar BPDU Guard por defecto:\nIOS: spanning-tree portfast bpduguard default\nNX-OS: spanning-tree port type edge bpduguard default", undefined, "Habilitar BPDU guard por defecto es una defensa crítica contra la conexión accidental de switches no autorizados en puertos de acceso, lo que podría causar una interrupción masiva de la red.");
        } else {
            createFinding('check-21', 'CIS L2.1', 'BPDU Guard Habilitado por Defecto', Severity.MEDIUM, FindingStatus.COMPLIANT, "BPDU Guard está habilitado por defecto en todo el switch.", "No se requiere acción.", configContent.match(/spanning-tree port(fast| type edge) bpduguard default/m));
        }

        if (osType === 'NX-OS' && nxosNeitherEdgeNetwork.length > 0) {
            createFinding('check-nxos-porttype', 'NX-OS Best Practice', 'Spanning Tree Port Type no Configurado', Severity.LOW, FindingStatus.NON_COMPLIANT, `Se encontraron ${nxosNeitherEdgeNetwork.length} interfaces de switchport en NX-OS sin un 'spanning-tree port type' explícito.`, "Configure el tipo de puerto Spanning Tree en todas las interfaces de switchport para optimizar la convergencia y la seguridad.\nUse 'spanning-tree port type edge' para puertos de acceso y 'spanning-tree port type network' para enlaces troncales a otros switches.", nxosNeitherEdgeNetwork.map(i => `interface ${i}`), "Definir explícitamente el tipo de puerto en NX-OS permite que Spanning Tree funcione de manera más eficiente y predecible, evitando retardos innecesarios en la activación de puertos de host y fortaleciendo los enlaces troncales.");
        }

        if (!configContent.includes("spanning-tree guard root")) {
            createFinding('check-22', 'CIS L2.2', 'Considerar Spanning Tree Root Guard', Severity.INFORMATIONAL, FindingStatus.NON_COMPLIANT, "Root Guard previene que switches no autorizados se conviertan en el root bridge.", "En interfaces que conectan a switches que no deben ser root, configure:\ninterface <nombre_interfaz>\n spanning-tree guard root\nend");
        }
     }


    addFinding(findings);
};