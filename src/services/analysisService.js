

import { FindingStatus } from '../constants.js';
import { checkSsh } from '../checks/sshChecks.js';
import { checkAaa } from '../checks/aaaChecks.js';
import { checkLoggingAndNtp } from '../checks/loggingChecks.js';
import { checkServices } from '../checks/serviceChecks.js';
import { checkSnmp } from '../checks/snmpChecks.js';
import { checkRouting } from '../checks/routingChecks.js';
import { checkInterfaces } from '../checks/interfaceChecks.js';
import { checkPasswords } from '../checks/passwordChecks.js';
import { checkGeneral } from '../checks/generalChecks.js';
import { checkVty } from '../checks/vtyChecks.js';

export const analyzeConfiguration = (fileName, configContent) => {
  return new Promise((resolve) => {
    // Simulate async operation
    setTimeout(() => {
      const findingsList = [];
      let totalChecks = 0;
      
      const isNxOS = /boot nxos|vdc|feature-set|bios:version/i.test(configContent);
      const osType = isNxOS ? 'NX-OS' : 'IOS';

      const addFinding = (finding) => {
        totalChecks++;
        findingsList.push(finding);
      };
      
      const addMultipleFindings = (findings) => {
        findings.forEach(f => {
             totalChecks++;
             findingsList.push(f);
        });
      };

      // Execute all check modules, passing the OS type
      checkGeneral(configContent, addMultipleFindings, osType);
      checkPasswords(configContent, addMultipleFindings, osType);
      checkServices(configContent, addMultipleFindings, osType);
      checkLoggingAndNtp(configContent, addMultipleFindings, osType);
      checkAaa(configContent, addMultipleFindings, osType);
      checkSsh(configContent, addMultipleFindings, osType);
      checkVty(configContent, addMultipleFindings, osType);
      checkSnmp(configContent, addMultipleFindings, osType);
      checkRouting(configContent, addMultipleFindings, osType);
      checkInterfaces(configContent, addMultipleFindings, osType);


      const summary = {
        osType,
        totalChecks: totalChecks,
        issuesFound: findingsList.filter(f => f.status === FindingStatus.NON_COMPLIANT || f.status === FindingStatus.ERROR).length,
        bySeverity: findingsList.reduce((acc, f) => {
          if (f.status === FindingStatus.NON_COMPLIANT || f.status === FindingStatus.ERROR) {
            acc[f.severity] = (acc[f.severity] || 0) + 1;
          }
          return acc;
        }, {}),
        byStatus: findingsList.reduce((acc, f) => {
          acc[f.status] = (acc[f.status] || 0) + 1;
          return acc;
        }, {}),
        overallScore: totalChecks > 0 ? Math.max(0, Math.round(((totalChecks - findingsList.filter(f => f.status === FindingStatus.NON_COMPLIANT).length) / totalChecks) * 100)) : 100,
      };

      const generatedReport = {
        fileName: fileName,
        analysisDate: new Date().toISOString(),
        summary: summary,
        findings: findingsList,
      };
      resolve(generatedReport);
    }, 200);
  });
};