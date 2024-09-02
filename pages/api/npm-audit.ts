import type { NextApiRequest, NextApiResponse } from 'next';
import { exec } from 'child_process';
import { promisify } from 'util';
import fs from 'fs';
import path from 'path';
import os from 'os';

const execPromise = promisify(exec);

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse
) {
  if (req.method !== 'POST') {
    return res.status(405).json({ message: 'Method Not Allowed' });
  }

  try {
    const { dependencies } = req.body;

    // Create a temporary directory
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'npm-audit-'));

    // Write dependencies to a temporary package.json
    const tempFile = path.join(tempDir, 'package.json');
    fs.writeFileSync(tempFile, JSON.stringify({ dependencies }, null, 2));

    console.log('Temporary package.json created at:', tempFile);
    console.log('package.json contents:', fs.readFileSync(tempFile, 'utf8'));

    // Create package-lock.json using npx to control npm version and network usage
    console.log('Creating package-lock.json...');
    try {
      // Use `npx npm install --package-lock-only --offline` to try avoiding network fetches
      await execPromise('npx npm install --package-lock-only --offline', { cwd: tempDir });
      console.log('package-lock.json contents:', fs.readFileSync(path.join(tempDir, 'package-lock.json'), 'utf8'));
    } catch (error) {
      console.error('Failed to create package-lock.json:', error);
      return res.status(500).json({ error: 'Failed to create package-lock.json', details: error.message });
    }

    // Run npm audit
    console.log('Running npm audit...');
    let stdout, stderr;
    try {
      const result = await execPromise('npx npm audit --json --omit=dev', { cwd: tempDir });
      stdout = result.stdout;
      stderr = result.stderr;
    } catch (error: any) {
      // npm audit exits with non-zero status if vulnerabilities are found
      stdout = error.stdout;
      stderr = error.stderr;
    }

    console.log('npm audit stdout:', stdout);
    console.log('npm audit stderr:', stderr);

    // Clean up
    fs.rmSync(tempDir, { recursive: true, force: true });

    if (stderr) {
      console.error('Audit stderr:', stderr);
    }

    // Parse audit output
    let auditOutput;
    try {
      auditOutput = JSON.parse(stdout);
    } catch (parseError) {
      console.error('Error parsing audit output:', parseError);
      return res.status(500).json({ 
        error: 'Failed to parse npm audit output', 
        details: parseError.message,
        stdout,
        stderr 
      });
    }

    const vulnerabilities = Object.entries(auditOutput.vulnerabilities || {}).map(([name, info]: [string, any]) => {
      const viaInfo = Array.isArray(info.via) ? info.via[0] : info.via;
      return {
        name,
        version: info.range || 'unknown',
        vulnerability: typeof viaInfo === 'object' ? viaInfo.title : viaInfo,
        severity: info.severity || 'unknown',
        recommendation: info.fixAvailable 
          ? `Upgrade ${info.fixAvailable.name} to version ${info.fixAvailable.version}` 
          : 'No specific recommendation',
        cvssScore: typeof viaInfo === 'object' ? viaInfo.cvss?.score : undefined,
        cvssVector: typeof viaInfo === 'object' ? viaInfo.cvss?.vectorString : undefined,
        source: typeof viaInfo === 'object' ? viaInfo.source : undefined,
        url: typeof viaInfo === 'object' ? viaInfo.url : undefined,
        cwe: typeof viaInfo === 'object' ? viaInfo.cwe : undefined,
      }
    });

    res.status(200).json({ 
      vulnerabilities,
      metadata: auditOutput.metadata
    });
  } catch (error: any) {
    console.error('Error performing npm audit:', error);
    res.status(500).json({ 
      error: 'Failed to perform npm audit', 
      details: error.message,
      stack: error.stack 
    });
  }
}
