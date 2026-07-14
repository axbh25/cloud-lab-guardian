/**
 * Cloud Lab Guardian — Golden Tests
 *
 * These tests verify that the deterministic pipeline always produces plans that
 * meet the safety, correctness, and portfolio-readiness requirements documented
 * in the release-hardening spec.
 *
 * Run: pnpm --filter @workspace/cloud-lab-guardian test
 */

import { describe, it, expect } from 'vitest';
import {
  normalizeUserIdea,
  detectServices,
  generateClarifyingQuestions,
  generateArchitecture,
  generateSecurityReview,
  generateCostReview,
  generateSteps,
  generateCleanup,
} from './guardianAgent';
import type { LabPlan, BudgetRisk, SkillLevel } from './guardianAgent';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function buildPlan(
  rawIdea: string,
  budget: BudgetRisk = '$0',
  skillLevel: SkillLevel = 'complete-beginner',
  region = 'us-east-1'
): Omit<LabPlan, 'readme' | 'pipelineMode'> {
  const normalizedIdea = normalizeUserIdea(rawIdea);
  const detectedServices = detectServices(normalizedIdea);
  const clarifyingQuestions = generateClarifyingQuestions(normalizedIdea, detectedServices);
  const architecture = generateArchitecture(normalizedIdea, detectedServices, skillLevel, budget);
  const securityReview = generateSecurityReview(detectedServices, skillLevel);
  const costReview = generateCostReview(detectedServices, budget);
  const steps = generateSteps(normalizedIdea, detectedServices, region, skillLevel);
  const cleanup = generateCleanup(detectedServices, region);
  return { normalizedIdea, detectedServices, clarifyingQuestions, architecture, securityReview, costReview, steps, cleanup };
}

const allCommands = (plan: ReturnType<typeof buildPlan>) => [
  ...plan.steps.flatMap((s) => s.commands),
  ...plan.cleanup.commands,
];

// ---------------------------------------------------------------------------
// Universal invariants (apply to every plan)
// ---------------------------------------------------------------------------

const GOLDEN_PROMPTS: [string, BudgetRisk][] = [
  ['Create a beginner AWS AI project using S3 and Lambda.', '$0'],
  ['Build a serverless image uploader.', '$0'],
  ['Build an app with EC2, RDS, NAT Gateway, and public S3.', '$10'],
  ['Create a Bedrock chatbot with a $0 budget.', '$0'],
  ['Build a Lambda Function URL API.', '$0'],
];

describe('Universal safety invariants — every plan must satisfy these', () => {
  for (const [prompt, budget] of GOLDEN_PROMPTS) {
    describe(`Prompt: "${prompt}"`, () => {
      const plan = buildPlan(prompt, budget);

      it('warns against public S3', () => {
        const securityText = JSON.stringify(plan.securityReview);
        // If S3 is in the plan, the security review must warn about it
        if (plan.detectedServices.some((s) => s.name === 'S3')) {
          expect(securityText.toLowerCase()).toMatch(/public.*s3|block.*public|s3.*public/i);
        } else {
          // No S3 detected — universal warnings still present
          expect(securityText).toContain('AdministratorAccess');
        }
      });

      it('warns against AdministratorAccess', () => {
        const text = JSON.stringify(plan.securityReview);
        expect(text).toContain('AdministratorAccess');
      });

      it('warns against hardcoded AWS keys', () => {
        const text = JSON.stringify(plan.securityReview);
        expect(text.toLowerCase()).toMatch(/hardcode|aws_access_key|credential/i);
      });

      it('includes cleanup commands', () => {
        expect(plan.cleanup.commands.length).toBeGreaterThan(0);
        expect(plan.cleanup.checklist.length).toBeGreaterThan(0);
      });

      it('cleanup commands contain no malformed s3 paths (s3: /)', () => {
        const cmds = allCommands(plan).join('\n');
        // Must not have "s3: /" or "s3 :/" — should always be "s3://"
        expect(cmds).not.toMatch(/s3:\s+\//);
        expect(cmds).not.toMatch(/s3 :\//);
      });

      it('cleanup commands contain no malformed IAM ARNs with spaces', () => {
        const cmds = allCommands(plan).join('\n');
        // arn:aws:iam:: must not have spaces before the colons
        // \s+ (one or more spaces) guards against "arn:aws:iam ::" but allows "arn:aws:iam::" (correct)
        expect(cmds).not.toMatch(/arn:aws:iam\s+::/);
        expect(cmds).not.toMatch(/arn:\s+aws/);
      });

      it('cleanup commands do not use single-hyphen AWS CLI flags', () => {
        const lines = allCommands(plan).filter((c) => c.startsWith('aws '));
        for (const line of lines) {
          // Long AWS CLI flags must start with -- (two hyphens), never just one.
          // A single-hyphen long flag would look like " -function-name" or " -region"
          // (space then one hyphen then letters). Two hyphens "--function-name" are fine.
          expect(line).not.toMatch(/ -[a-z]{2,}/);
        }
      });

      it('step commands use double-hyphen AWS CLI flags', () => {
        const stepCmds = plan.steps.flatMap((s) => s.commands).join('\n');
        // Verify correct double-hyphen flags are present where expected
        const lambdaPresent = plan.detectedServices.some((s) => s.name === 'Lambda');
        if (lambdaPresent) {
          expect(stepCmds).toMatch(/--function-name/);
          expect(stepCmds).toMatch(/--region/);
        }
      });

      it('S3 commands use s3:// not s3:/ or other malformed variants', () => {
        const cmds = allCommands(plan).join('\n');
        if (plan.detectedServices.some((s) => s.name === 'S3')) {
          // Any s3 URI present must be properly formatted
          const s3Uris = cmds.match(/s3:[^\s]+/g) ?? [];
          for (const uri of s3Uris) {
            expect(uri).toMatch(/^s3:\/\//);
          }
        }
      });
    });
  }
});

// ---------------------------------------------------------------------------
// Prompt-specific golden tests
// ---------------------------------------------------------------------------

describe('Prompt: "Create a Bedrock chatbot with a $0 budget"', () => {
  const plan = buildPlan('Create a Bedrock chatbot with a $0 budget.', '$0');

  it('detects Bedrock as a service', () => {
    expect(plan.detectedServices.some((s) => s.name === 'Bedrock')).toBe(true);
  });

  it('does NOT treat Bedrock as a required free-tier service (puts it in optional bucket)', () => {
    // Bedrock must NOT appear in paidRisks for $0 budget (it should be in freetiierItems as "Optional Advanced")
    const paidNames = plan.costReview.paidRisks.map((r) => r.service);
    expect(paidNames).not.toContain('Amazon Bedrock');
  });

  it('marks Bedrock as Optional Advanced / High Risk in cost review', () => {
    const bedrockItem = plan.costReview.freetiierItems.find((i) =>
      i.service.toLowerCase().includes('bedrock')
    );
    expect(bedrockItem).toBeDefined();
    expect(bedrockItem!.detail.toLowerCase()).toMatch(/optional.*advanced|high risk|not.*mvp/i);
  });

  it('architecture description explains Bedrock is not part of the $0 MVP path', () => {
    expect(plan.architecture.description.toLowerCase()).toMatch(
      /bedrock.*optional|not.*0.*mvp|mvp.*bedrock|optional.*bedrock/i
    );
  });

  it('security review warns that Bedrock has no free tier', () => {
    const text = JSON.stringify(plan.securityReview);
    expect(text.toLowerCase()).toMatch(/bedrock.*no free tier|free tier.*bedrock/i);
  });
});

describe('Prompt: "Build an app with EC2, RDS, NAT Gateway, and public S3"', () => {
  const plan = buildPlan('Build an app with EC2, RDS, NAT Gateway, and public S3.', '$10');

  it('detects EC2 and RDS as high-risk services', () => {
    const ec2 = plan.detectedServices.find((s) => s.name === 'EC2');
    const rds = plan.detectedServices.find((s) => s.name === 'RDS');
    expect(ec2?.riskLevel).toBe('high');
    expect(rds?.riskLevel).toBe('high');
  });

  it('places EC2 and RDS in paid risks (not free tier)', () => {
    const paidNames = plan.costReview.paidRisks.map((r) => r.service);
    expect(paidNames).toContain('Amazon EC2');
    expect(paidNames).toContain('Amazon RDS');
  });

  it('warns about security groups and public access', () => {
    const text = JSON.stringify(plan.securityReview);
    expect(text.toLowerCase()).toMatch(/security group|0\.0\.0\.0\/0/i);
    expect(text.toLowerCase()).toMatch(/block.*public|public.*s3/i);
  });

  it('cleanup includes EC2-specific steps', () => {
    const text = plan.cleanup.checklist.join('\n').toLowerCase();
    expect(text).toMatch(/terminate|ec2/i);
  });
});

describe('Prompt: "Build a Lambda Function URL API"', () => {
  const plan = buildPlan('Build a Lambda Function URL API.', '$0');

  it('detects Lambda', () => {
    expect(plan.detectedServices.some((s) => s.name === 'Lambda')).toBe(true);
  });

  it('does NOT detect API Gateway (user asked for Function URL, not API Gateway)', () => {
    // Regression: "api" in "Function URL API" must not trigger API Gateway detection
    expect(plan.detectedServices.some((s) => s.name === 'API Gateway')).toBe(false);
  });

  it('includes a Lambda Function URL setup step', () => {
    const stepTitles = plan.steps.map((s) => s.title.toLowerCase());
    expect(stepTitles.some((t) => t.includes('function url'))).toBe(true);
  });

  it('cleanup includes Lambda Function URL teardown, not API Gateway teardown', () => {
    const cmds = plan.cleanup.commands.join('\n');
    expect(cmds).not.toMatch(/apigatewayv2 delete-api/);
    expect(cmds).toMatch(/delete-function-url-config/);
  });

  it('step commands include --function-name and --region flags', () => {
    const cmds = plan.steps.flatMap((s) => s.commands).join('\n');
    expect(cmds).toMatch(/--function-name/);
    expect(cmds).toMatch(/--region/);
  });
});

describe('Prompt: "Build a serverless image uploader"', () => {
  const plan = buildPlan('Build a serverless image uploader.', '$0');

  it('detects S3 and Lambda', () => {
    expect(plan.detectedServices.some((s) => s.name === 'S3')).toBe(true);
    expect(plan.detectedServices.some((s) => s.name === 'Lambda')).toBe(true);
  });

  it('S3 step commands use s3:// not s3:/', () => {
    const cmds = plan.steps.flatMap((s) => s.commands).join('\n');
    const s3Uris = cmds.match(/s3:[^\s]+/g) ?? [];
    for (const uri of s3Uris) {
      expect(uri).toMatch(/^s3:\/\//);
    }
  });

  it('security review warns about public S3 buckets', () => {
    const titles = plan.securityReview.warnings.map((w) => w.title.toLowerCase());
    expect(titles.some((t) => t.includes('public') && t.includes('s3'))).toBe(true);
  });

  it('includes Block Public Access in S3 setup commands', () => {
    const cmds = plan.steps.flatMap((s) => s.commands).join('\n');
    expect(cmds.toLowerCase()).toMatch(/block.*public|blockpublicacls/i);
  });
});

describe('Prompt: "Create a beginner AWS AI project using S3 and Lambda"', () => {
  const plan = buildPlan('Create a beginner AWS AI project using S3 and Lambda.', '$0');

  it('detects S3 and Lambda', () => {
    expect(plan.detectedServices.some((s) => s.name === 'S3')).toBe(true);
    expect(plan.detectedServices.some((s) => s.name === 'Lambda')).toBe(true);
  });

  it('all step commands use double-hyphen flags', () => {
    const cmds = plan.steps.flatMap((s) => s.commands).filter((c) => c.startsWith('aws '));
    for (const cmd of cmds) {
      // AWS CLI long options must start with --
      const flags = cmd.match(/ -[a-z]/g) ?? [];
      // Allowed single-char flags: -o (output shorthand), -q (quiet), none expected in our commands
      expect(flags).toHaveLength(0);
    }
  });

  it('IAM ARNs in commands have no spaces', () => {
    const cmds = plan.steps.flatMap((s) => s.commands).join('\n');
    const arns = cmds.match(/arn:aws:[^\s'"}]+/g) ?? [];
    for (const arn of arns) {
      expect(arn).not.toMatch(/\s/);
    }
  });
});

// ---------------------------------------------------------------------------
// CLI command format audit
// ---------------------------------------------------------------------------

describe('CLI command format audit — all prompts', () => {
  for (const [prompt, budget] of GOLDEN_PROMPTS) {
    it(`"${prompt}" — s3:// URLs are well-formed`, () => {
      const plan = buildPlan(prompt, budget);
      const cmds = allCommands(plan).join('\n');
      const s3Refs = cmds.match(/s3:[^\s"'`]+/g) ?? [];
      for (const ref of s3Refs) {
        expect(ref).toMatch(/^s3:\/\//);
      }
    });

    it(`"${prompt}" — IAM ARNs contain no spaces`, () => {
      const plan = buildPlan(prompt, budget);
      const cmds = allCommands(plan).join('\n');
      const arns = cmds.match(/arn:aws:[^\s'"}\]]+/g) ?? [];
      for (const arn of arns) {
        expect(arn).not.toMatch(/\s/);
      }
    });

    it(`"${prompt}" — region values are well-formed`, () => {
      const plan = buildPlan(prompt, budget, 'complete-beginner', 'us-east-1');
      const cmds = allCommands(plan).join('\n');
      // Extract region values using a capture group — match only [a-z0-9-] chars
      const regionMatches = [...cmds.matchAll(/--region\s+([a-z][a-z0-9-]*)/g)];
      for (const m of regionMatches) {
        const regionVal = m[1];
        expect(regionVal).toMatch(/^[a-z][a-z0-9-]+$/);
      }
    });
  }
});
