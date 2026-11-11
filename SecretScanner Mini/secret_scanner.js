const fs = require("fs");

function calculateEntropy(value) {
  if (typeof value !== "string" || value.length === 0) {
    return 0;
  }

  const counts = new Map();

  for (const char of value) {
    counts.set(char, (counts.get(char) || 0) + 1);
  }

  let entropy = 0;

  for (const count of counts.values()) {
    const p = count / value.length;
    entropy += -p * Math.log2(p);
  }

  return entropy;
}

function scanLine(line, lineNumber) {
  const findings = [];

  const patterns = [
    { type: "AWS_ACCESS_KEY", regex: /AKIA[0-9A-Z]{16}/g },
    { type: "GITHUB_TOKEN", regex: /ghp_[a-zA-Z0-9]{20,}/g },
    { type: "PRIVATE_KEY", regex: /BEGIN (?:[A-Z]+ )?PRIVATE KEY/g },
    {
      type: "GENERIC_API_KEY",
      regex: /(?:api_key|apikey|secret|token)["'\s:=]+([a-zA-Z0-9_\-]{16,})/gi,
    },
  ];

  for (const pattern of patterns) {
    const matches = line.matchAll(pattern.regex);

    for (const match of matches) {
      const value = match[1] || match[0];
      findings.push({
        type: pattern.type,
        value: value,
        line: lineNumber,
        entropy: 0,
      });
    }
  }

  const longTokenRegex = /[A-Za-z0-9+/=_-]{20,}/g;
  const tokenMatches = line.matchAll(longTokenRegex);

  for (const match of tokenMatches) {
    const token = match[0];
    const alreadyFound = findings.some((finding) => finding.value === token);
    if (alreadyFound) {
      continue;
    }

    const entropy = calculateEntropy(token);

    if (entropy > 4.5) {
      findings.push({
        type: "HIGH_ENTROPY",
        value: token,
        line: lineNumber,
        entropy: Number(entropy.toFixed(4)),
      });
    }
  }

  return findings;
}

function scanFile(filePath) {
  let content;

  try {
    content = fs.readFileSync(filePath, "utf8");
  } catch (error) {
    console.error(`Error reading file "${filePath}": ${error.message}`);
    return null;
  }

  const lines = content.split(/\r?\n/);
  const findings = [];

  for (let i = 0; i < lines.length; i++) {
    const lineNumber = i + 1;
    const lineFindings = scanLine(lines[i], lineNumber);
    findings.push(...lineFindings);
  }

  return findings;
}

function main() {
  const filePath = process.argv[2] || "sample_secrets.txt";
  const findings = scanFile(filePath);

  if (findings === null) {
    return;
  }

  if (findings.length === 0) {
    console.log("CLEAN");
  } else {
    for (const finding of findings) {
      console.log(
        `${finding.type} at line ${finding.line}: ${finding.value} | entropy ${finding.entropy}`,
      );
    }
  }

  try {
    fs.writeFileSync("secrets.json", JSON.stringify(findings, null, 2), "utf8");
  } catch (error) {
    console.error(`Error writing secrets.json: ${error.message}`);
    return;
  }

  return;
}

main();
