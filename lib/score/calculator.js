module.exports.calcScore = function calcScore(findings) {
  const weights = {
    critical: 25,
    high: 10,
    medium: 5,
    low: 2,
    info: 0
  };

  if (!Array.isArray(findings)) findings = [];
  const score = 100 - findings.reduce((sum, finding) => sum + (weights[finding.severity] || 0), 0);
  return {
    score: Math.max(score, 0),
    breakdown: findings.reduce((acc, finding) => {
      acc[finding.severity] = (acc[finding.severity] || 0) + 1;
      return acc;
    }, {})
  };
}
