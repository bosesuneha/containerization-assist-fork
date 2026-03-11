/**
 * Scan Image Tool - Standardized Implementation
 *
 * Scans Docker images for security vulnerabilities
 * Uses standardized helpers for consistency
 * Supports scanning across specific or all Docker contexts
 */

import { setupToolContext } from '@/lib/tool-context-helpers';
import type { ToolContext } from '@/core/context';

import { createSecurityScanner } from '@/infra/security/scanner';
import { Success, Failure, type Result } from '@/types';
import { getKnowledgeForCategory } from '@/knowledge/index';
import type { KnowledgeMatch } from '@/knowledge/types';
import { type ScanImageParams } from './schema';
import { formatVulnerabilities, buildStatusSummary, pluralize } from '@/lib/summary-helpers';
import { scanImageToolDefinition } from './types';
import { listDockerContexts, resolveDockerContext } from '@/infra/docker/context';

interface DockerScanResult {
  vulnerabilities?: Array<{
    id?: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NEGLIGIBLE' | 'UNKNOWN';
    package?: string;
    version?: string;
    description?: string;
    fixedVersion?: string;
  }>;
  summary?: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    negligible: number;
    unknown: number;
    total: number;
  };
  scanTime?: string;
  metadata?: {
    image: string;
  };
}

/**
 * Actionable fix recommendation that groups related vulnerabilities
 */
export interface FixAction {
  type: 'UPGRADE_PACKAGE';
  action: string;
  current: string;
  recommended: string;
  package: string;
  vulnerabilitiesFixed: number;
  severityCounts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    negligible: number;
    unknown: number;
  };
  vulnerabilityIds: string[];
}

export interface ScanImageResult {
  /**
   * Natural language summary for user display.
   * 1-3 sentences describing the scan outcome, vulnerability counts, and recommendations.
   * @example "🔒 Security scan failed. Found 142 vulnerabilities (2 critical, 5 high, 12 medium). 1 remediation recommendation available."
   */
  summary?: string;
  success: boolean;
  scanner: string;
  /**
   * The Docker context used for this scan.
   * Only set when a specific context was requested or when scanning all contexts.
   */
  context?: string;
  recommendedActions?: FixAction[];
  remediationGuidance?: Array<{
    vulnerability: string;
    recommendation: string;
    severity?: string;
    example?: string;
  }>;
  vulnerabilities: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    negligible: number;
    unknown: number;
    total: number;
  };
  vulnerabilityDetails?: Array<{
    id: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NEGLIGIBLE' | 'UNKNOWN';
    package: string;
    version: string;
    description: string;
    fixedVersion?: string;
    /** Docker context where this vulnerability was found (only in multi-context scans) */
    context?: string;
  }>;
  scanTime: string;
  passed: boolean;
  /**
   * Per-context scan results when scanning across multiple Docker contexts.
   * Only present when context="all" is specified.
   */
  contextResults?: ContextScanResult[];
}

/**
 * Scan result for a single Docker context (used in multi-context scans)
 */
export interface ContextScanResult {
  /** Docker context name */
  context: string;
  /** Docker daemon endpoint for this context */
  endpoint: string;
  /** Whether the scan succeeded for this context */
  success: boolean;
  /** Error message if scan failed for this context */
  error?: string;
  /** Whether the scan passed the severity threshold */
  passed?: boolean;
  /** Vulnerability counts for this context */
  vulnerabilities?: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    negligible: number;
    unknown: number;
    total: number;
  };
}

/**
 * Analyze vulnerabilities and generate actionable fix recommendations
 * Groups vulnerabilities by package for cleaner output
 */
function analyzeFixActions(
  vulnerabilities: Array<{
    id: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NEGLIGIBLE' | 'UNKNOWN';
    package: string;
    version: string;
    fixedVersion?: string;
  }>,
): FixAction[] {
  const fixable = vulnerabilities.filter((v) => v.fixedVersion !== undefined);
  if (fixable.length === 0) return [];

  const normalizeVersion = (value: string | undefined): string => {
    if (value === undefined) return 'unknown';
    return value.trim() === '' ? 'unknown' : value;
  };

  const byPackageVersion = new Map<string, typeof fixable>();
  for (const vuln of fixable) {
    const currentVersion = normalizeVersion(vuln.version);
    const fixedVersion = normalizeVersion(vuln.fixedVersion);
    const key = `${vuln.package}::${currentVersion}::${fixedVersion}`;
    const grouped = byPackageVersion.get(key) || [];
    grouped.push(vuln);
    byPackageVersion.set(key, grouped);
  }

  const actions: FixAction[] = Array.from(byPackageVersion.entries()).map(([, vulns]) => {
    const severityCounts = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      negligible: 0,
      unknown: 0,
    };

    for (const vuln of vulns) {
      switch (vuln.severity) {
        case 'CRITICAL':
          severityCounts.critical += 1;
          break;
        case 'HIGH':
          severityCounts.high += 1;
          break;
        case 'MEDIUM':
          severityCounts.medium += 1;
          break;
        case 'LOW':
          severityCounts.low += 1;
          break;
        case 'NEGLIGIBLE':
          severityCounts.negligible += 1;
          break;
        case 'UNKNOWN':
          severityCounts.unknown += 1;
          break;
      }
    }

    const vulnerabilityIds = [...new Set(vulns.map((v) => v.id))].slice(0, 5);
    const packageName = vulns[0]?.package ?? 'unknown';
    const currentVersion = normalizeVersion(vulns[0]?.version);
    const fixedVersion = normalizeVersion(vulns[0]?.fixedVersion);

    return {
      type: 'UPGRADE_PACKAGE',
      action: `Upgrade ${packageName}`,
      current: `${packageName}: ${currentVersion}`,
      recommended: `${packageName}: ${fixedVersion}`,
      package: packageName,
      vulnerabilitiesFixed: vulns.length,
      severityCounts,
      vulnerabilityIds,
    };
  });

  const severityOrder: Array<keyof FixAction['severityCounts']> = [
    'critical',
    'high',
    'medium',
    'low',
    'negligible',
    'unknown',
  ];

  actions.sort((a, b) => {
    for (const severity of severityOrder) {
      if (b.severityCounts[severity] !== a.severityCounts[severity]) {
        return b.severityCounts[severity] - a.severityCounts[severity];
      }
    }
    return b.vulnerabilitiesFixed - a.vulnerabilitiesFixed;
  });

  return actions.slice(0, 5);
}

/**
 * Scan image handler - direct execution without wrapper
 */
async function handleScanImage(
  params: ScanImageParams,
  context: ToolContext,
): Promise<Result<ScanImageResult>> {
  if (!params || typeof params !== 'object') {
    return Failure('Invalid parameters provided', {
      message: 'Parameters must be a valid object',
      hint: 'Tool received invalid or missing parameters',
      resolution: 'Ensure parameters are provided as a JSON object',
    });
  }
  const { logger, timer } = setupToolContext(context, 'scan-image');

  const {
    scanner = 'osv',
    severity,
    scanType = 'vulnerability',
    enableAISuggestions = true,
    context: dockerContext,
  } = params;

  if (scanType !== 'vulnerability') {
    return Failure(`Scan type '${scanType}' is not supported`, {
      message: 'Only vulnerability scans are currently supported',
      hint: 'Use scanType="vulnerability" for image vulnerability checks',
      resolution: 'Update scanType to "vulnerability" and retry',
    });
  }

  // Map severity parameter to threshold
  const finalSeverityThreshold = severity
    ? (severity.toLowerCase() as 'low' | 'medium' | 'high' | 'critical')
    : 'high';

  const imageId = params.imageId;

  if (!imageId) {
    return Failure('No image specified. Provide imageId parameter.', {
      message: 'Missing required parameter: imageId',
      hint: 'Image ID or name must be specified to scan',
      resolution: 'Add imageId parameter with the Docker image ID or name to scan',
    });
  }

  // Handle multi-context scanning when context="all"
  if (dockerContext === 'all') {
    return handleMultiContextScan(params, context, logger, timer);
  }

  // Resolve Docker context to endpoint if a specific context is requested
  let dockerHost: string | undefined;
  if (dockerContext) {
    const resolved = await resolveDockerContext(dockerContext, logger);
    if (!resolved.ok) {
      return Failure(resolved.error, resolved.guidance);
    }
    dockerHost = resolved.value;
    logger.info({ context: dockerContext, dockerHost }, 'Resolved Docker context');
  }

  try {
    logger.info(
      { scanner, severityThreshold: finalSeverityThreshold, scanType, context: dockerContext },
      'Starting image security scan',
    );

    const securityScanner = createSecurityScanner(logger, scanner, dockerHost);

    logger.info(
      { imageId, scanner, scanType, context: dockerContext },
      'Scanning image for vulnerabilities',
    );

    // Scan image using security scanner
    const scanResultWrapper = await securityScanner.scanImage(imageId);

    if (!scanResultWrapper.ok) {
      return Failure(
        `Failed to scan image: ${scanResultWrapper.error ?? 'Unknown error'}`,
        scanResultWrapper.guidance,
      );
    }

    const scanResult = scanResultWrapper.value;

    // Convert BasicScanResult to DockerScanResult
    const dockerScanResult: DockerScanResult = {
      vulnerabilities: scanResult.vulnerabilities.map((v) => ({
        id: v.id,
        severity: v.severity,
        package: v.package,
        version: v.version,
        description: v.description,
        ...(v.fixedVersion !== undefined && { fixedVersion: v.fixedVersion }),
      })),
      summary: {
        critical: scanResult.criticalCount,
        high: scanResult.highCount,
        medium: scanResult.mediumCount,
        low: scanResult.lowCount,
        negligible: scanResult.negligibleCount,
        unknown: scanResult.unknownCount,
        total: scanResult.totalVulnerabilities,
      },
      scanTime: scanResult.scanDate.toISOString(),
      metadata: {
        image: imageId,
      },
    };

    // Determine if scan passed based on threshold
    const { passed } = evaluateThreshold(scanResult, finalSeverityThreshold);

    // Get knowledge-based remediation guidance for vulnerabilities
    const remediationGuidance = await getRemediationGuidance(
      enableAISuggestions,
      dockerScanResult,
      logger,
    );

    // Generate summary
    const vulnSummary = formatVulnerabilities({
      critical: scanResult.criticalCount,
      high: scanResult.highCount,
      medium: scanResult.mediumCount,
      low: scanResult.lowCount,
      total: scanResult.totalVulnerabilities,
    });

    const contextLabel = dockerContext ? ` [context: ${dockerContext}]` : '';
    const remediationText =
      remediationGuidance.length > 0
        ? ` ${pluralize(remediationGuidance.length, 'remediation')} available.`
        : '';

    const summary = buildStatusSummary(
      passed,
      `🔒 Security scan passed (${scanner})${contextLabel}. ${vulnSummary}.${remediationText}`,
      `🔒 Security scan failed (${scanner})${contextLabel}. ${vulnSummary}.${remediationText}`,
    );

    const vulnerabilityDetails =
      dockerScanResult.vulnerabilities && dockerScanResult.vulnerabilities.length > 0
        ? dockerScanResult.vulnerabilities.map((v) => ({
            id: v.id ?? 'UNKNOWN',
            severity: v.severity,
            package: v.package ?? 'unknown',
            version: v.version ?? 'unknown',
            description: v.description ?? 'No description available',
            ...(v.fixedVersion !== undefined && { fixedVersion: v.fixedVersion }),
          }))
        : undefined;

    const recommendedActions =
      vulnerabilityDetails && vulnerabilityDetails.length > 0
        ? analyzeFixActions(vulnerabilityDetails)
        : undefined;

    const result: ScanImageResult = {
      summary,
      success: true,
      scanner,
      ...(dockerContext && { context: dockerContext }),
      ...(recommendedActions && recommendedActions.length > 0 && { recommendedActions }),
      ...(remediationGuidance.length > 0 && { remediationGuidance }),
      vulnerabilities: {
        critical: scanResult.criticalCount,
        high: scanResult.highCount,
        medium: scanResult.mediumCount,
        low: scanResult.lowCount,
        negligible: scanResult.negligibleCount,
        unknown: scanResult.unknownCount,
        total: scanResult.totalVulnerabilities,
      },
      ...(vulnerabilityDetails && { vulnerabilityDetails }),
      scanTime: dockerScanResult.scanTime ?? new Date().toISOString(),
      passed,
    };

    timer.end({
      vulnerabilities: scanResult.totalVulnerabilities,
      critical: scanResult.criticalCount,
      high: scanResult.highCount,
      passed,
    });

    logger.info(
      {
        imageId,
        vulnerabilities: scanResult.totalVulnerabilities,
        passed,
        context: dockerContext,
      },
      'Image scan completed',
    );

    return Success(result);
  } catch (error) {
    timer.error(error);
    logger.error({ error, context: dockerContext }, 'Image scan failed');

    const errorMessage = error instanceof Error ? error.message : String(error);
    return Failure(errorMessage, {
      message: errorMessage,
      hint: 'An unexpected error occurred during the security scan',
      resolution:
        'Verify that the scanner is installed and accessible, the image exists, and you have proper permissions',
    });
  }
}

/**
 * Handle scanning across all available Docker contexts.
 * Lists all Docker contexts, scans the image in each, and aggregates results.
 */
async function handleMultiContextScan(
  params: ScanImageParams,
  _context: ToolContext,
  logger: ReturnType<typeof setupToolContext>['logger'],
  timer: ReturnType<typeof setupToolContext>['timer'],
): Promise<Result<ScanImageResult>> {
  const { scanner = 'osv', severity, enableAISuggestions = true, imageId } = params;

  const finalSeverityThreshold = severity
    ? (severity.toLowerCase() as 'low' | 'medium' | 'high' | 'critical')
    : 'high';

  // List all Docker contexts
  const contextsResult = await listDockerContexts(logger);
  if (!contextsResult.ok) {
    return Failure(contextsResult.error, contextsResult.guidance);
  }

  const dockerContexts = contextsResult.value;
  logger.info(
    { contextCount: dockerContexts.length, contexts: dockerContexts.map((c) => c.name) },
    'Scanning image across all Docker contexts',
  );

  // Aggregate counters
  const aggregated = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    negligible: 0,
    unknown: 0,
    total: 0,
  };
  const allVulnerabilityDetails: ScanImageResult['vulnerabilityDetails'] = [];
  const contextResults: ContextScanResult[] = [];
  let allPassed = true;
  let anySucceeded = false;

  // Scan each context sequentially to avoid overwhelming Docker daemons
  for (const dockerCtx of dockerContexts) {
    const ctxName = dockerCtx.name;
    const endpoint = dockerCtx.dockerEndpoint;

    if (dockerCtx.error) {
      logger.warn({ context: ctxName, error: dockerCtx.error }, 'Skipping context with error');
      contextResults.push({
        context: ctxName,
        endpoint,
        success: false,
        error: dockerCtx.error,
      });
      continue;
    }

    logger.info({ context: ctxName, endpoint }, 'Scanning in Docker context');

    try {
      // Resolve the context endpoint
      const resolved = await resolveDockerContext(ctxName, logger);
      if (!resolved.ok) {
        logger.warn(
          { context: ctxName, error: resolved.error },
          'Failed to resolve context endpoint',
        );
        contextResults.push({
          context: ctxName,
          endpoint,
          success: false,
          error: resolved.error,
        });
        continue;
      }

      const dockerHost = resolved.value;
      const securityScanner = createSecurityScanner(logger, scanner, dockerHost);
      const scanResultWrapper = await securityScanner.scanImage(imageId);

      if (!scanResultWrapper.ok) {
        logger.warn(
          { context: ctxName, error: scanResultWrapper.error },
          'Scan failed for context',
        );
        contextResults.push({
          context: ctxName,
          endpoint,
          success: false,
          error: scanResultWrapper.error,
        });
        continue;
      }

      const scanResult = scanResultWrapper.value;
      const { passed } = evaluateThreshold(scanResult, finalSeverityThreshold);
      anySucceeded = true;

      if (!passed) {
        allPassed = false;
      }

      // Aggregate vulnerability counts
      aggregated.critical += scanResult.criticalCount;
      aggregated.high += scanResult.highCount;
      aggregated.medium += scanResult.mediumCount;
      aggregated.low += scanResult.lowCount;
      aggregated.negligible += scanResult.negligibleCount;
      aggregated.unknown += scanResult.unknownCount;
      aggregated.total += scanResult.totalVulnerabilities;

      // Aggregate vulnerability details with context annotation
      if (scanResult.vulnerabilities.length > 0) {
        for (const v of scanResult.vulnerabilities) {
          allVulnerabilityDetails.push({
            id: v.id,
            severity: v.severity,
            package: v.package,
            version: v.version,
            description: v.description,
            ...(v.fixedVersion !== undefined && { fixedVersion: v.fixedVersion }),
            context: ctxName,
          });
        }
      }

      contextResults.push({
        context: ctxName,
        endpoint,
        success: true,
        passed,
        vulnerabilities: {
          critical: scanResult.criticalCount,
          high: scanResult.highCount,
          medium: scanResult.mediumCount,
          low: scanResult.lowCount,
          negligible: scanResult.negligibleCount,
          unknown: scanResult.unknownCount,
          total: scanResult.totalVulnerabilities,
        },
      });

      logger.info(
        { context: ctxName, vulnerabilities: scanResult.totalVulnerabilities, passed },
        'Context scan completed',
      );
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.warn({ context: ctxName, error: errorMessage }, 'Exception scanning context');
      contextResults.push({
        context: ctxName,
        endpoint,
        success: false,
        error: errorMessage,
      });
    }
  }

  if (!anySucceeded) {
    timer.error(new Error('All context scans failed'));
    return Failure('Failed to scan image in any Docker context', {
      message: 'No Docker context could successfully scan the image',
      hint: 'The image may not exist in any context, or all Docker daemons may be unreachable',
      resolution:
        'Verify the image exists with "docker images" and check Docker daemon status. ' +
        'Run "docker context ls" to see available contexts.',
    });
  }

  // Build remediation guidance from aggregated results
  const remediationGuidance = await getRemediationGuidance(
    enableAISuggestions,
    {
      vulnerabilities: allVulnerabilityDetails.map((v) => ({
        id: v.id,
        severity: v.severity,
        package: v.package,
        version: v.version,
        description: v.description,
        ...(v.fixedVersion !== undefined && { fixedVersion: v.fixedVersion }),
      })),
    },
    logger,
  );

  // Build summary
  const succeededCount = contextResults.filter((r) => r.success).length;
  const failedCount = contextResults.filter((r) => !r.success).length;
  const vulnSummary = formatVulnerabilities({
    critical: aggregated.critical,
    high: aggregated.high,
    medium: aggregated.medium,
    low: aggregated.low,
    total: aggregated.total,
  });

  const contextSummary =
    failedCount > 0
      ? ` Scanned ${succeededCount}/${dockerContexts.length} contexts (${failedCount} failed).`
      : ` Scanned ${succeededCount} contexts.`;

  const remediationText =
    remediationGuidance.length > 0
      ? ` ${pluralize(remediationGuidance.length, 'remediation')} available.`
      : '';

  const summary = buildStatusSummary(
    allPassed,
    `🔒 Security scan passed across all contexts (${scanner}).${contextSummary} ${vulnSummary}.${remediationText}`,
    `🔒 Security scan failed in some contexts (${scanner}).${contextSummary} ${vulnSummary}.${remediationText}`,
  );

  const recommendedActions =
    allVulnerabilityDetails.length > 0 ? analyzeFixActions(allVulnerabilityDetails) : undefined;

  const result: ScanImageResult = {
    summary,
    success: true,
    scanner,
    context: 'all',
    ...(recommendedActions && recommendedActions.length > 0 && { recommendedActions }),
    ...(remediationGuidance.length > 0 && { remediationGuidance }),
    vulnerabilities: aggregated,
    ...(allVulnerabilityDetails.length > 0 && { vulnerabilityDetails: allVulnerabilityDetails }),
    scanTime: new Date().toISOString(),
    passed: allPassed,
    contextResults,
  };

  timer.end({
    vulnerabilities: aggregated.total,
    critical: aggregated.critical,
    high: aggregated.high,
    passed: allPassed,
    contextsScanned: succeededCount,
    contextsFailed: failedCount,
  });

  logger.info(
    {
      imageId,
      totalVulnerabilities: aggregated.total,
      passed: allPassed,
      contextsScanned: succeededCount,
      contextsFailed: failedCount,
    },
    'Multi-context image scan completed',
  );

  return Success(result);
}

/**
 * Evaluate whether a scan result passes the severity threshold.
 */
function evaluateThreshold(
  scanResult: { criticalCount: number; highCount: number; mediumCount: number; lowCount: number },
  threshold: 'low' | 'medium' | 'high' | 'critical',
): { passed: boolean; vulnerabilityCount: number } {
  const thresholdMap: Record<string, string[]> = {
    critical: ['critical'],
    high: ['critical', 'high'],
    medium: ['critical', 'high', 'medium'],
    low: ['critical', 'high', 'medium', 'low'],
  };

  const failingSeverities = thresholdMap[threshold] ?? thresholdMap['high'] ?? ['critical', 'high'];
  let vulnerabilityCount = 0;

  for (const sev of failingSeverities) {
    if (sev === 'critical') {
      vulnerabilityCount += scanResult.criticalCount;
    } else if (sev === 'high') {
      vulnerabilityCount += scanResult.highCount;
    } else if (sev === 'medium') {
      vulnerabilityCount += scanResult.mediumCount;
    } else if (sev === 'low') {
      vulnerabilityCount += scanResult.lowCount;
    }
  }

  return { passed: vulnerabilityCount === 0, vulnerabilityCount };
}

/**
 * Get knowledge-based remediation guidance for scan vulnerabilities.
 */
async function getRemediationGuidance(
  enableAISuggestions: boolean,
  dockerScanResult: Pick<DockerScanResult, 'vulnerabilities'>,
  logger: ReturnType<typeof setupToolContext>['logger'],
): Promise<NonNullable<ScanImageResult['remediationGuidance']>> {
  if (
    !enableAISuggestions ||
    !dockerScanResult.vulnerabilities ||
    dockerScanResult.vulnerabilities.length === 0
  ) {
    return [];
  }

  try {
    const vulnSummary = dockerScanResult.vulnerabilities
      .slice(0, 10)
      .map((v) => `${v.package}:${v.version} (${v.severity})`)
      .join(', ');

    const securityKnowledge = await getKnowledgeForCategory('security', vulnSummary);
    const generalKnowledge = await getKnowledgeForCategory('security', undefined);

    const guidance = [
      ...securityKnowledge.map((match: KnowledgeMatch) => ({
        vulnerability: 'General',
        recommendation: match.entry.recommendation,
        ...(match.entry.severity && { severity: match.entry.severity }),
        ...(match.entry.example && { example: match.entry.example }),
      })),
      ...generalKnowledge.map((match: KnowledgeMatch) => ({
        vulnerability: 'Best Practice',
        recommendation: match.entry.recommendation,
        ...(match.entry.severity && { severity: match.entry.severity }),
        ...(match.entry.example && { example: match.entry.example }),
      })),
    ];

    logger.info({ guidanceCount: guidance.length }, 'Added knowledge-based remediation guidance');
    return guidance;
  } catch (error) {
    logger.debug({ error }, 'Failed to get remediation guidance, continuing without');
    return [];
  }
}

/**
 * Scan image tool
 */
export const scanImage = handleScanImage;

import { tool } from '@/types/tool';

export default tool({
  ...scanImageToolDefinition,
  handler: handleScanImage,
});
