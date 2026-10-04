const path = require('path');
const fs = require('fs');
const { loadReceipt } = require('../monitoring/receipt');
const { generateRevokeSteps, assessUserImpact, generateBreachNotice } = require('../incident/response');

async function incidentCommand(options) {
  const targetPath = path.resolve(options.path);
  const verbose = options.verbose;
  const companyName = options.company || 'Your Company';

  let receipt;
  try {
    receipt = await loadReceipt(targetPath);
  } catch (e) {
    console.error('No recent scan found. Run shrine scan first.');
    process.exit(1);
  }

  if (!receipt || !receipt.findings || receipt.findings.length === 0) {
    console.error('No findings in receipt. Run shrine scan first.');
    process.exit(1);
  }

  const findings = receipt.findings;

  const revokeSteps = generateRevokeSteps(findings);
  const impact = assessUserImpact(findings, { filesScanned: receipt.filesScanned, tables: receipt.tables });
  const notice = generateBreachNotice(impact, { companyName });

  console.log('\x1b[31m\x1b[1mINCIDENT MODE\x1b[0m\n');

  console.log('Revoke Steps:');
  revokeSteps.forEach((step, i) => {
    console.log(`  ${i + 1}. ${step}`);
  });
  console.log('');

  console.log('Impact Assessment:');
  console.log(`  Severity: ${impact.severity}`);
  console.log(`  Affected Users: ${impact.affectedUsers}`);
  console.log(`  Data Exposed: ${impact.dataExposed.join(', ') || 'none'}`);
  console.log(`  Summary: ${impact.summary}`);
  console.log('');

  console.log('Breach Notice Preview:');
  console.log(notice.slice(0, 300) + '...');
  console.log('');

  const reportPath = path.join(targetPath, '.shrine', `incident-report-${Date.now()}.md`);
  const reportContent = `${notice}

## Revoke Steps
${revokeSteps.map((s, i) => `${i + 1}. ${s}`).join('\n')}

## Impact Assessment
\`\`\`json
${JSON.stringify(impact, null, 2)}
\`\`\`
`;

  try {
    fs.mkdirSync(path.dirname(reportPath), { recursive: true });
    fs.writeFileSync(reportPath, reportContent);
    if (verbose) console.log(`Report written to ${reportPath}`);
  } catch (e) {
    console.error('Failed to write incident report:', e.message);
  }
}

module.exports = { incidentCommand };