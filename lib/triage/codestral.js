const fs = require('fs').promises;
const path = require('path');

/**
 * Triage findings with Codestral (Mistral AI). Sends only the masked
 * match plus the source line with the secret masked - never raw secrets.
 * Marks each finding triage: 'important' | 'noise'.
 */
async function triageFindings(findings, options = {}) {
  const apiKey = options.apiKey || process.env.MISTRAL_API_KEY;
  if (!apiKey || findings.length === 0) {
    return findings;
  }

  // Build request items: masked match + line (secret masked in-line)
  const items = [];
  for (const finding of findings) {
    if (!finding.file || !finding.line) {
      continue;
    }
    let lineContent = '';
    try {
      const filePath = path.isAbsolute(finding.file)
        ? finding.file
        : path.join(options.scanRoot || process.cwd(), finding.file);
      const content = await fs.readFile(filePath, 'utf-8');
      lineContent = content.split('\n')[finding.line - 1] || '';
    } catch (error) {
      lineContent = '';
    }

    const masked = finding.redacted || finding.match || '';
    const safeLine = finding.match ? lineContent.split(finding.match).join(masked) : lineContent;

    items.push({
      file: finding.file,
      line: finding.line,
      type: finding.type,
      match: masked,
      context: safeLine
    });
  }

  if (items.length === 0) {
    return findings;
  }

  // Batch in chunks of 20
  const BATCH = 20;
  for (let i = 0; i < items.length; i += BATCH) {
    const batch = items.slice(i, i + BATCH);
    const prompt = `You are triaging potential secret detections from a code scanner.
For each item decide: "important" (likely a real exposed secret) or "noise" (false positive, placeholder, or sample value).

Respond ONLY with a JSON array like: [{"id":1,"verdict":"important"}]

Items:
${JSON.stringify(batch.map((item, idx) => ({ id: idx + 1, ...item })), null, 2)}`;

    try {
      const res = await fetch('https://api.mistral.ai/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${apiKey}`
        },
        body: JSON.stringify({
          model: 'codestral-latest',
          messages: [{ role: 'user', content: prompt }],
          temperature: 0
        })
      });

      if (!res.ok) {
        const errText = await res.text();
        console.log(`\nCodestral triage failed (HTTP ${res.status}). Showing all findings.`);
        return findings;
      }

      const data = await res.json();
      const text = (data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content) || '';
      const jsonMatch = text.match(/\[[\s\S]*\]/);
      const verdicts = jsonMatch ? JSON.parse(jsonMatch[0]) : [];
      const verdictMap = new Map(verdicts.map(v => [v.id, v.verdict]));

      for (let j = 0; j < batch.length; j++) {
        findings[i + j].triage = verdictMap.get(j + 1) === 'noise' ? 'noise' : 'important';
      }
    } catch (error) {
      console.log(`\nCodestral triage failed: ${error.message}. Showing all findings.`);
      return findings;
    }
  }

  return findings;
}

module.exports = { triageFindings };
