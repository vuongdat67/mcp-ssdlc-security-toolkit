/**
 * Workspace Diagnostic Tools Tests
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  workspaceSnapshot,
  environmentDiagnostics,
  validatePath,
  runDiagnosticPlaybook,
} from '../../../src/tools/workspace/workspace-diagnostics.js';

describe('Workspace Diagnostic Tools', () => {
  describe('workspaceSnapshot', () => {
    it('should create a workspace snapshot with default options', async () => {
      const result = await workspaceSnapshot({});
      
      expect(result).toHaveProperty('root');
      expect(result).toHaveProperty('os');
      expect(result).toHaveProperty('timestamp');
      expect(result).toHaveProperty('structure');
      expect(result).toHaveProperty('stats');
      expect(result).toHaveProperty('environment');
      expect(['windows', 'linux', 'darwin']).toContain(result.os);
    });

    it('should respect maxDepth option', async () => {
      const result = await workspaceSnapshot({ maxDepth: 1 });
      
      expect(result.stats.totalDirs).toBeDefined();
      expect(result.structure).toBeDefined();
    });

    it('should detect build system', async () => {
      const result = await workspaceSnapshot({});
      
      expect(result.buildSystem).toBeDefined();
      expect(result.buildSystem?.type).toBeDefined();
    });

    it('should include environment info', async () => {
      const result = await workspaceSnapshot({});
      
      expect(result.environment).toBeDefined();
      expect(result.environment.cwd).toBeDefined();
      expect(result.environment.shell).toBeDefined();
    });
  });

  describe('environmentDiagnostics', () => {
    it('should run diagnostics for all categories', async () => {
      const result = await environmentDiagnostics({ categories: ['all'] });
      
      expect(Array.isArray(result)).toBe(true);
      expect(result.length).toBeGreaterThan(0);
      
      // Each result should have required fields
      result.forEach(diagnostic => {
        expect(diagnostic).toHaveProperty('category');
        expect(diagnostic).toHaveProperty('status');
        expect(diagnostic).toHaveProperty('message');
        expect(['ok', 'warning', 'error']).toContain(diagnostic.status);
      });
    });

    it('should run diagnostics for specific category', async () => {
      const result = await environmentDiagnostics({ categories: ['node'] });
      
      expect(Array.isArray(result)).toBe(true);
      const nodeResults = result.filter(r => r.category === 'node');
      expect(nodeResults.length).toBeGreaterThan(0);
    });

    it('should detect Node.js installation', async () => {
      const result = await environmentDiagnostics({ categories: ['node'] });
      
      const nodeCheck = result.find(r => r.message.includes('Node.js'));
      expect(nodeCheck).toBeDefined();
    });
  });

  describe('validatePath', () => {
    it('should validate existing path', async () => {
      const result = await validatePath({
        targetPath: process.cwd(),
      });
      
      expect(result.exists).toBe(true);
      expect(result.type).toBe('directory');
      expect(result.accessible).toBe(true);
    });

    it('should validate non-existing path', async () => {
      const result = await validatePath({
        targetPath: '/non/existent/path/that/does/not/exist',
      });
      
      expect(result.exists).toBe(false);
      expect(result.type).toBe('none');
    });

    it('should provide absolute and relative paths', async () => {
      const result = await validatePath({
        targetPath: '.',
      });
      
      expect(result.absolutePath).toBeDefined();
      expect(result.relativePath).toBeDefined();
    });

    it('should find similar paths for typos', async () => {
      const result = await validatePath({
        targetPath: 'packges', // typo of 'packages'
        findSimilar: true,
      });
      
      // May or may not find suggestions depending on workspace
      expect(result).toHaveProperty('suggestions');
    });
  });

  describe('runDiagnosticPlaybook', () => {
    it('should run node-setup playbook', async () => {
      const result = await runDiagnosticPlaybook({
        playbook: 'node-setup',
      });
      
      expect(result.playbook).toBe('node-setup');
      expect(Array.isArray(result.results)).toBe(true);
      expect(Array.isArray(result.commands)).toBe(true);
    });

    it('should run build-check playbook', async () => {
      const result = await runDiagnosticPlaybook({
        playbook: 'build-check',
      });
      
      expect(result.playbook).toBe('build-check');
      expect(result.results).toBeDefined();
      expect(result.commands).toBeDefined();
    });

    it('should run path-debug playbook', async () => {
      const result = await runDiagnosticPlaybook({
        playbook: 'path-debug',
      });
      
      expect(result.playbook).toBe('path-debug');
      const pathResult = result.results.find(r => r.category === 'path-debug');
      expect(pathResult).toBeDefined();
    });

    it('should run env-verify playbook', async () => {
      const result = await runDiagnosticPlaybook({
        playbook: 'env-verify',
      });
      
      expect(result.playbook).toBe('env-verify');
      expect(result.results.length).toBeGreaterThan(0);
    });

    it('should provide suggested commands', async () => {
      const result = await runDiagnosticPlaybook({
        playbook: 'node-setup',
      });
      
      expect(result.commands.length).toBeGreaterThan(0);
      // Commands should be strings
      result.commands.forEach(cmd => {
        expect(typeof cmd).toBe('string');
      });
    });
  });
});
