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

    if (!dependencies || typeof dependencies !== 'object') {
      return res.status(400).json({ error: 'Invalid dependencies format' });
    }

    // Log dependencies to verify
    console.log('Received dependencies:', dependencies);

    // Create a temporary directory
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'npm-audit-'));

    // Write dependencies to a temporary package.json
    const tempFile = path.join(tempDir, 'package.json');

    // Ensure package.json has required "name" and "version" fields
    const packageJsonContent = {
      name: "temp-package",  // Default package name
      version: "1.0.0",      // Default version
      dependencies: dependencies,  // Add uploaded dependencies
    };

    fs.writeFileSync(tempFile, JSON.stringify(packageJsonContent, null, 2));

    console.log('Temporary package.json created at:', tempFile);
    console.log('package.json contents:', fs.readFileSync(tempFile, 'utf8'));

    // Generate package-lock.json
    console.log('Generating package-lock.json...');
    try {
      await execPromise('npm install --package-lock-only --ignore-scripts', { cwd: tempDir });
      console.log('Generated package-lock.json:', fs.readFileSync(path.join(tempDir, 'package-lock.json'), 'utf8'));
    } catch (error) {
      console.error('Failed to create package-lock.json:', error);
      return res.status(500).json({ error: 'Failed to create package-lock.json', details: error.message });
    }

    // Install dependencies to populate node_modules
    console.log('Installing dependencies (offline mode) to populate node_modules...');
    try {
      await execPromise('npm install --ignore-scripts', { cwd: tempDir });
      console.log('Dependencies installed.');
    } catch (error) {
      console.error('Failed to install dependencies:', error);
    }

    // Run npm audit
    console.log('Running npm audit...');
    let stdoutAudit, stderrAudit;
    try {
      const result = await execPromise(`npm audit --json --omit=dev`, { cwd: tempDir });
      stdoutAudit = result.stdout;
      stderrAudit = result.stderr;
    } catch (error: any) {
      stdoutAudit = error.stdout;
      stderrAudit = error.stderr;
    }

    console.log('npm audit stdout:', stdoutAudit);
    console.log('npm audit stderr:', stderrAudit);

    // Clean up
    fs.rmSync(tempDir, { recursive: true, force: true });

    if (stderrAudit) {
      console.error('Audit stderr:', stderrAudit);
    }

    // Parse audit output
    let auditOutput;
    try {
      auditOutput = JSON.parse(stdoutAudit);
    } catch (parseError) {
      console.error('Error parsing audit output:', parseError);
      return res.status(500).json({ 
        error: 'Failed to parse npm audit output', 
        details: parseError.message,
        stdoutAudit,
        stderrAudit 
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
