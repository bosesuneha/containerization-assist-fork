/**
 * Unit Tests: Docker Context Resolution
 * Tests the Docker context listing and resolution utility
 */

import { jest, describe, it, expect, beforeEach } from '@jest/globals';

// Mock child_process before importing the module
const mockExecFile = jest.fn<() => Promise<{ stdout: string; stderr: string }>>();

jest.mock('node:child_process', () => ({
  execFile: mockExecFile,
}));

jest.mock('node:util', () => ({
  promisify: () => mockExecFile,
}));

function createMockLogger() {
  return {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
    trace: jest.fn(),
    fatal: jest.fn(),
    child: jest.fn().mockReturnThis(),
  } as any;
}

import { listDockerContexts, resolveDockerContext } from '../../../../src/infra/docker/context';

describe('Docker Context Resolution', () => {
  let logger: any;

  beforeEach(() => {
    jest.clearAllMocks();
    logger = createMockLogger();
  });

  describe('listDockerContexts', () => {
    it('should list Docker contexts from CLI output', async () => {
      const contextOutput = [
        JSON.stringify({
          Current: true,
          Name: 'default',
          Description: 'Current DOCKER_HOST based configuration',
          DockerEndpoint: 'unix:///var/run/docker.sock',
        }),
        JSON.stringify({
          Current: false,
          Name: 'colima',
          Description: 'colima',
          DockerEndpoint: 'unix:///Users/user/.colima/default/docker.sock',
        }),
      ].join('\n');

      mockExecFile.mockResolvedValue({ stdout: contextOutput, stderr: '' });

      const result = await listDockerContexts(logger);

      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.value).toHaveLength(2);
        expect(result.value[0]).toEqual({
          name: 'default',
          description: 'Current DOCKER_HOST based configuration',
          dockerEndpoint: 'unix:///var/run/docker.sock',
          current: true,
        });
        expect(result.value[1]).toEqual({
          name: 'colima',
          description: 'colima',
          dockerEndpoint: 'unix:///Users/user/.colima/default/docker.sock',
          current: false,
        });
      }
    });

    it('should handle contexts with errors', async () => {
      const contextOutput = JSON.stringify({
        Current: false,
        Name: 'broken-context',
        Description: 'A broken context',
        DockerEndpoint: 'tcp://unreachable:2375',
        Error: 'connection refused',
      });

      mockExecFile.mockResolvedValue({ stdout: contextOutput, stderr: '' });

      const result = await listDockerContexts(logger);

      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.value).toHaveLength(1);
        expect(result.value[0].error).toBe('connection refused');
        expect(result.value[0].name).toBe('broken-context');
      }
    });

    it('should fail when Docker CLI returns empty output', async () => {
      mockExecFile.mockResolvedValue({ stdout: '', stderr: '' });

      const result = await listDockerContexts(logger);

      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error).toContain('No Docker contexts found');
      }
    });

    it('should fail when Docker CLI is not available', async () => {
      const error = new Error('ENOENT: docker not found') as NodeJS.ErrnoException;
      error.code = 'ENOENT';
      mockExecFile.mockRejectedValue(error);

      const result = await listDockerContexts(logger);

      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error).toContain('Failed to list Docker contexts');
      }
    });

    it('should skip unparseable lines and succeed with valid ones', async () => {
      const contextOutput = [
        'not valid json',
        JSON.stringify({
          Current: true,
          Name: 'default',
          Description: 'Default',
          DockerEndpoint: 'unix:///var/run/docker.sock',
        }),
      ].join('\n');

      mockExecFile.mockResolvedValue({ stdout: contextOutput, stderr: '' });

      const result = await listDockerContexts(logger);

      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.value).toHaveLength(1);
        expect(result.value[0].name).toBe('default');
      }
      expect(logger.debug).toHaveBeenCalled();
    });

    it('should fail when all lines are unparseable', async () => {
      mockExecFile.mockResolvedValue({ stdout: 'garbage\nmore garbage\n', stderr: '' });

      const result = await listDockerContexts(logger);

      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error).toContain('Failed to parse any Docker contexts');
      }
    });

    it('should handle contexts with missing optional fields', async () => {
      const contextOutput = JSON.stringify({
        Name: 'minimal',
        Current: false,
      });

      mockExecFile.mockResolvedValue({ stdout: contextOutput, stderr: '' });

      const result = await listDockerContexts(logger);

      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.value).toHaveLength(1);
        expect(result.value[0].name).toBe('minimal');
        expect(result.value[0].description).toBe('');
        expect(result.value[0].dockerEndpoint).toBe('');
        expect(result.value[0].current).toBe(false);
      }
    });

    it('should log stderr output as debug', async () => {
      const contextOutput = JSON.stringify({
        Current: true,
        Name: 'default',
        Description: 'Default',
        DockerEndpoint: 'unix:///var/run/docker.sock',
      });

      mockExecFile.mockResolvedValue({
        stdout: contextOutput,
        stderr: 'WARNING: some deprecation notice',
      });

      const result = await listDockerContexts(logger);

      expect(result.ok).toBe(true);
      expect(logger.debug).toHaveBeenCalledWith(
        { stderr: 'WARNING: some deprecation notice' },
        'Docker context ls stderr output',
      );
    });
  });

  describe('resolveDockerContext', () => {
    it('should resolve a context name to its endpoint', async () => {
      mockExecFile.mockResolvedValue({
        stdout: 'unix:///var/run/docker.sock\n',
        stderr: '',
      });

      const result = await resolveDockerContext('default', logger);

      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.value).toBe('unix:///var/run/docker.sock');
      }
    });

    it('should resolve a TCP endpoint', async () => {
      mockExecFile.mockResolvedValue({
        stdout: 'tcp://192.168.1.10:2375\n',
        stderr: '',
      });

      const result = await resolveDockerContext('remote-host', logger);

      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.value).toBe('tcp://192.168.1.10:2375');
      }
    });

    it('should fail when context has no endpoint', async () => {
      mockExecFile.mockResolvedValue({ stdout: '\n', stderr: '' });

      const result = await resolveDockerContext('empty-context', logger);

      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error).toContain('has no endpoint');
      }
    });

    it('should fail when context does not exist', async () => {
      mockExecFile.mockRejectedValue(new Error('context "nonexistent" does not exist'));

      const result = await resolveDockerContext('nonexistent', logger);

      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error).toContain("Failed to resolve Docker context 'nonexistent'");
        expect(result.guidance).toBeDefined();
        expect(result.guidance?.resolution).toContain('docker context ls');
      }
    });

    it('should fail when Docker CLI is not available', async () => {
      const error = new Error('ENOENT') as NodeJS.ErrnoException;
      error.code = 'ENOENT';
      mockExecFile.mockRejectedValue(error);

      const result = await resolveDockerContext('default', logger);

      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error).toContain('Failed to resolve Docker context');
      }
    });
  });
});
