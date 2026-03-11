/**
 * Docker context resolution utility.
 *
 * Provides functions to list and resolve Docker CLI contexts,
 * enabling tools to target specific Docker daemons beyond the default.
 *
 * Docker contexts are managed by the Docker CLI (`docker context`) and each
 * context maps to a Docker daemon endpoint (Unix socket or TCP URL).
 */

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import type { Logger } from 'pino';

import { extractErrorMessage } from '@/lib/errors';
import { Result, Success, Failure } from '@/types';

const execFileAsync = promisify(execFile);

/**
 * Represents a Docker CLI context with its endpoint information.
 */
export interface DockerContext {
  /** Context name (e.g., "default", "colima", "desktop-linux") */
  name: string;
  /** Human-readable description */
  description: string;
  /** Docker daemon endpoint (e.g., "unix:///var/run/docker.sock", "tcp://192.168.1.10:2375") */
  dockerEndpoint: string;
  /** Whether this context is the currently active one */
  current: boolean;
  /** Error message if context has issues (e.g., unreachable endpoint) */
  error?: string;
}

/**
 * Raw JSON output from `docker context ls --format '{{json .}}'`.
 */
interface DockerContextRaw {
  Current?: boolean;
  // docker cli >= 23.x uses "Current", older uses "*" in Name field
  Name: string;
  Description?: string;
  DockerEndpoint?: string;
  Error?: string;
}

/**
 * List all available Docker CLI contexts.
 *
 * Executes `docker context ls` and parses the output into structured data.
 * Falls back gracefully if the Docker CLI is not available.
 *
 * @param logger - Logger instance for debug output
 * @returns Result containing array of DockerContext objects
 */
export async function listDockerContexts(logger: Logger): Promise<Result<DockerContext[]>> {
  try {
    const { stdout, stderr } = await execFileAsync(
      'docker',
      ['context', 'ls', '--format', '{{json .}}'],
      { timeout: 10000 },
    );

    if (stderr) {
      logger.debug({ stderr }, 'Docker context ls stderr output');
    }

    if (!stdout.trim()) {
      return Failure('No Docker contexts found', {
        message: 'docker context ls returned empty output',
        hint: 'Docker CLI may not be properly configured',
        resolution: 'Ensure Docker is installed and run: docker context ls',
      });
    }

    const contexts: DockerContext[] = [];

    // Each line is a JSON object
    for (const line of stdout.trim().split('\n')) {
      const trimmed = line.trim();
      if (!trimmed) continue;

      try {
        const raw: DockerContextRaw = JSON.parse(trimmed);

        contexts.push({
          name: raw.Name,
          description: raw.Description ?? '',
          dockerEndpoint: raw.DockerEndpoint ?? '',
          current: raw.Current === true,
          ...(raw.Error ? { error: raw.Error } : {}),
        });
      } catch (parseError) {
        logger.debug(
          { line: trimmed, error: extractErrorMessage(parseError) },
          'Failed to parse Docker context line',
        );
      }
    }

    if (contexts.length === 0) {
      return Failure('Failed to parse any Docker contexts', {
        message: 'docker context ls output could not be parsed',
        hint: 'Docker CLI output format may be unexpected',
        resolution: 'Run "docker context ls" manually to verify Docker configuration',
      });
    }

    logger.debug(
      { contextCount: contexts.length, contexts: contexts.map((c) => c.name) },
      'Listed Docker contexts',
    );

    return Success(contexts);
  } catch (error) {
    const errorMessage = extractErrorMessage(error);
    logger.debug({ error: errorMessage }, 'Failed to list Docker contexts');

    return Failure(`Failed to list Docker contexts: ${errorMessage}`, {
      message: 'Could not list Docker contexts',
      hint: 'The Docker CLI may not be installed or accessible',
      resolution: 'Ensure Docker CLI is installed and in PATH. Run "docker context ls" to verify.',
    });
  }
}

/**
 * Resolve a Docker context name to its daemon endpoint.
 *
 * Returns the Docker endpoint (socket path or TCP URL) for the specified context.
 * The endpoint can be used as DOCKER_HOST or to create a targeted Docker client.
 *
 * @param contextName - Name of the Docker context to resolve
 * @param logger - Logger instance for debug output
 * @returns Result containing the Docker endpoint string (e.g., "unix:///var/run/docker.sock")
 */
export async function resolveDockerContext(
  contextName: string,
  logger: Logger,
): Promise<Result<string>> {
  try {
    const { stdout } = await execFileAsync(
      'docker',
      ['context', 'inspect', contextName, '--format', '{{.Endpoints.docker.Host}}'],
      { timeout: 10000 },
    );

    const endpoint = stdout.trim();
    if (!endpoint) {
      return Failure(`Docker context '${contextName}' has no endpoint`, {
        message: `Context '${contextName}' does not have a Docker endpoint configured`,
        hint: 'The context may be misconfigured or incomplete',
        resolution: `Run "docker context inspect ${contextName}" to check its configuration`,
      });
    }

    logger.debug({ contextName, endpoint }, 'Resolved Docker context endpoint');
    return Success(endpoint);
  } catch (error) {
    const errorMessage = extractErrorMessage(error);
    logger.debug({ error: errorMessage, contextName }, 'Failed to resolve Docker context');

    return Failure(`Failed to resolve Docker context '${contextName}': ${errorMessage}`, {
      message: `Docker context '${contextName}' could not be resolved`,
      hint: 'The context name may be incorrect or Docker CLI may not be available',
      resolution: `Run "docker context ls" to see available contexts. Available context names can be used with the context parameter.`,
    });
  }
}
