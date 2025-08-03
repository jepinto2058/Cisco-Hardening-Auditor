import { FindingStatus } from '../constants.js';

export const generateComparisonReport = (reportBefore, reportAfter) => {
    const mitigatedFindings = [];
    const trulyPendingFindings = []; 
    const newFindings = [];

    const findingsBeforeMap = new Map(reportBefore.findings.map(f => [f.id, f]));
    const findingsAfterMap = new Map(reportAfter.findings.map(f => [f.id, f]));

    // Find new and pending findings
    for (const [id, findingAfter] of findingsAfterMap.entries()) {
        const findingBefore = findingsBeforeMap.get(id);

        if (findingAfter.status === FindingStatus.NON_COMPLIANT) {
            if (!findingBefore || findingBefore.status === FindingStatus.COMPLIANT) {
                // It's a new issue if it didn't exist before, or was compliant before
                newFindings.push(findingAfter);
            } else {
                // It was and still is a non-compliant issue
                trulyPendingFindings.push(findingAfter);
            }
        }
    }

    // Find mitigated findings
    for (const [id, findingBefore] of findingsBeforeMap.entries()) {
        if (findingBefore.status === FindingStatus.NON_COMPLIANT) {
            const findingAfter = findingsAfterMap.get(id);
            // It's mitigated if it was non-compliant and is now compliant
            if (findingAfter && findingAfter.status === FindingStatus.COMPLIANT) {
                mitigatedFindings.push(findingAfter);
            }
        }
    }

    return {
        mitigatedCount: mitigatedFindings.length,
        pendingCount: trulyPendingFindings.length,
        newCount: newFindings.length,
        scoreBefore: reportBefore.summary.overallScore,
        scoreAfter: reportAfter.summary.overallScore,
        mitigatedFindings,
        pendingFindings: trulyPendingFindings,
        newFindings,
        fileNameBefore: reportBefore.fileName,
        fileNameAfter: reportAfter.fileName,
    };
};

export const generateDeviceComparisonReport = (reportA, reportB) => {
    const onlyInA = [];
    const onlyInB = [];
    const common = [];

    const findingsAMap = new Map(reportA.findings.map(f => [f.id, f]));
    const findingsBMap = new Map(reportB.findings.map(f => [f.id, f]));
    const allFindingIds = new Set([...findingsAMap.keys(), ...findingsBMap.keys()]);

    for (const id of allFindingIds) {
        const findingA = findingsAMap.get(id);
        const findingB = findingsBMap.get(id);

        const isNonCompliantA = findingA?.status === FindingStatus.NON_COMPLIANT;
        const isNonCompliantB = findingB?.status === FindingStatus.NON_COMPLIANT;

        if (isNonCompliantA && isNonCompliantB) {
            common.push(findingA); // Push finding from A, they are equivalent
        } else if (isNonCompliantA && !isNonCompliantB) {
            onlyInA.push(findingA);
        } else if (!isNonCompliantA && isNonCompliantB) {
            onlyInB.push(findingB);
        }
    }

    return {
        reportA,
        reportB,
        onlyInA,
        onlyInB,
        common,
    };
};
