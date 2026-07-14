/**
 * Cloud Lab Guardian — Deterministic Agent Pipeline v0.1.0
 * Rule-based AWS lab plan generator. No paid APIs required.
 * Optionally calls a Lambda Function URL if LAB_GUARDIAN_API_URL is set.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type SkillLevel = "complete-beginner" | "some-experience" | "intermediate";
export type BudgetRisk = "$0" | "$1" | "$5" | "$10";
export type PipelineMode = "local" | "lambda" | "lambda-fallback";

export interface LabPlan {
  normalizedIdea: string;
  detectedServices: DetectedService[];
  clarifyingQuestions: string[];
  architecture: ArchitectureSection;
  securityReview: SecurityReview;
  costReview: CostReview;
  steps: Step[];
  cleanup: CleanupSection;
  readme: string;
  pipelineMode: PipelineMode;
}

export interface DetectedService {
  name: string;
  awsName: string;
  icon: string;
  riskLevel: "safe" | "caution" | "high";
  freetier: string;
}

export interface ArchitectureSection {
  description: string;
  components: ArchitectureComponent[];
  diagram: string;
}

export interface ArchitectureComponent {
  name: string;
  purpose: string;
  awsService: string;
  beginner_tip: string;
}

export interface SecurityReview {
  warnings: SecurityWarning[];
  iamRecommendations: string[];
  bestPractices: string[];
}

export interface SecurityWarning {
  level: "critical" | "warning" | "info";
  title: string;
  description: string;
}

export interface CostReview {
  estimatedMonthly: string;
  freetiierItems: CostItem[];
  paidRisks: CostItem[];
  budgetAdvice: string;
}

export interface CostItem {
  service: string;
  detail: string;
  risk: "free" | "low" | "medium" | "high";
}

export interface Step {
  number: number;
  title: string;
  commands: string[];
  description: string;
  consoleLink?: string;
}

export interface CleanupSection {
  checklist: string[];
  commands: string[];
  estimatedTime: string;
}

// ---------------------------------------------------------------------------
// Service Detection Rules
// ---------------------------------------------------------------------------

interface ServiceRule {
  keywords: string[];
  service: DetectedService;
}

const SERVICE_RULES: ServiceRule[] = [
  {
    keywords: ["lambda", "serverless", "function", "trigger"],
    service: {
      name: "Lambda",
      awsName: "AWS Lambda",
      icon: "λ",
      riskLevel: "safe",
      freetier: "1M requests/month + 400,000 GB-seconds free forever",
    },
  },
  {
    keywords: ["s3", "bucket", "storage", "upload", "file", "image", "photo", "blob", "object"],
    service: {
      name: "S3",
      awsName: "Amazon S3",
      icon: "🗄",
      riskLevel: "caution",
      freetier: "5 GB storage + 20K GET + 2K PUT requests free for 12 months",
    },
  },
  {
    keywords: ["api", "rest", "http", "endpoint", "gateway", "webhook", "backend"],
    service: {
      name: "API Gateway",
      awsName: "Amazon API Gateway",
      icon: "🔌",
      riskLevel: "safe",
      freetier: "1M HTTP API calls/month free for 12 months",
    },
  },
  {
    keywords: ["dynamodb", "nosql", "database", "db", "table", "dynamo", "data"],
    service: {
      name: "DynamoDB",
      awsName: "Amazon DynamoDB",
      icon: "🗃",
      riskLevel: "safe",
      freetier: "25 GB storage + 25 read/write capacity units free forever",
    },
  },
  {
    keywords: ["rds", "mysql", "postgres", "postgresql", "sql", "relational"],
    service: {
      name: "RDS",
      awsName: "Amazon RDS",
      icon: "🏦",
      riskLevel: "high",
      freetier: "750 hours/month db.t2.micro free for 12 months ONLY (then billed)",
    },
  },
  {
    keywords: ["ec2", "virtual machine", "vm", "instance", "server", "compute"],
    service: {
      name: "EC2",
      awsName: "Amazon EC2",
      icon: "🖥",
      riskLevel: "high",
      freetier: "750 hours/month t2.micro free for 12 months ONLY (then billed)",
    },
  },
  {
    keywords: ["cloudwatch", "logs", "monitoring", "metrics", "alarm", "log"],
    service: {
      name: "CloudWatch",
      awsName: "Amazon CloudWatch",
      icon: "📊",
      riskLevel: "safe",
      freetier: "10 custom metrics + 10 alarms + 5 GB log ingestion free",
    },
  },
  {
    keywords: ["cognito", "auth", "authentication", "login", "user pool", "sign in", "oauth"],
    service: {
      name: "Cognito",
      awsName: "Amazon Cognito",
      icon: "🔐",
      riskLevel: "safe",
      freetier: "50,000 monthly active users (MAUs) free for user pools",
    },
  },
  {
    keywords: ["sqs", "queue", "message", "messaging", "async"],
    service: {
      name: "SQS",
      awsName: "Amazon SQS",
      icon: "📨",
      riskLevel: "safe",
      freetier: "1M requests/month free forever",
    },
  },
  {
    keywords: ["sns", "notification", "email", "sms", "push", "alert"],
    service: {
      name: "SNS",
      awsName: "Amazon SNS",
      icon: "🔔",
      riskLevel: "safe",
      freetier: "1M publishes + 100K HTTP deliveries free forever",
    },
  },
  {
    keywords: ["cloudfront", "cdn", "distribution", "edge", "cache"],
    service: {
      name: "CloudFront",
      awsName: "Amazon CloudFront",
      icon: "🌐",
      riskLevel: "safe",
      freetier: "1 TB data transfer + 10M requests free per month for 12 months",
    },
  },
  {
    keywords: ["iam", "role", "policy", "permission", "access", "security"],
    service: {
      name: "IAM",
      awsName: "AWS IAM",
      icon: "🛡",
      riskLevel: "safe",
      freetier: "Always free — no charge for IAM",
    },
  },
  {
    keywords: ["bedrock", "ai", "ml", "machine learning", "llm", "chatbot", "gpt", "generative", "claude", "titan"],
    service: {
      name: "Bedrock",
      awsName: "Amazon Bedrock",
      icon: "🤖",
      riskLevel: "high",
      freetier: "No free tier — billed per token used",
    },
  },
  {
    keywords: ["sagemaker", "training", "model training", "deep learning", "notebook"],
    service: {
      name: "SageMaker",
      awsName: "Amazon SageMaker",
      icon: "🧠",
      riskLevel: "high",
      freetier: "2-month free trial for limited instance types only",
    },
  },
  {
    keywords: ["step functions", "workflow", "orchestration", "state machine", "step function"],
    service: {
      name: "Step Functions",
      awsName: "AWS Step Functions",
      icon: "🔄",
      riskLevel: "safe",
      freetier: "4,000 state transitions/month free forever",
    },
  },
  {
    keywords: ["amplify", "hosting", "static site", "frontend", "react", "web app", "website"],
    service: {
      name: "Amplify",
      awsName: "AWS Amplify",
      icon: "⚡",
      riskLevel: "safe",
      freetier: "15 GB served + 1,000 build minutes free/month for 12 months",
    },
  },
];

// ---------------------------------------------------------------------------
// Agent Pipeline Functions
// ---------------------------------------------------------------------------

/** Step 1: Normalize the user's idea — clean up and standardize the input. */
export function normalizeUserIdea(rawIdea: string): string {
  return rawIdea
    .trim()
    .replace(/\s+/g, " ")
    .replace(/[^\w\s,.()\-?!:]/g, "")
    .toLowerCase()
    .replace(/^./, (c) => c.toUpperCase());
}

/** Step 2: Detect which AWS services the idea involves. */
export function detectServices(idea: string): DetectedService[] {
  const lower = idea.toLowerCase();
  const detected = new Map<string, DetectedService>();

  for (const rule of SERVICE_RULES) {
    if (rule.keywords.some((kw) => lower.includes(kw))) {
      detected.set(rule.service.name, { ...rule.service });
    }
  }

  // "function url" / "function url api" → user explicitly wants Lambda Function URL, not API Gateway
  if (lower.includes("function url")) {
    detected.delete("API Gateway");
    // Ensure Lambda is present (it's the host for Function URLs)
    if (!detected.has("Lambda")) {
      detected.set("Lambda", { ...SERVICE_RULES[0].service });
    }
  }

  // Default: assume a basic serverless project if nothing detected
  if (detected.size === 0) {
    detected.set("Lambda", { ...SERVICE_RULES[0].service });
    detected.set("API Gateway", { ...SERVICE_RULES[2].service });
    detected.set("DynamoDB", { ...SERVICE_RULES[3].service });
  }

  // Always add CloudWatch and IAM as baseline
  if (!detected.has("CloudWatch")) {
    detected.set("CloudWatch", { ...SERVICE_RULES[6].service });
  }
  if (!detected.has("IAM")) {
    detected.set("IAM", { ...SERVICE_RULES[11].service });
  }

  return Array.from(detected.values());
}

/** Step 3: Generate clarifying questions based on the idea and services. */
export function generateClarifyingQuestions(
  idea: string,
  services: DetectedService[]
): string[] {
  const lower = idea.toLowerCase();
  const questions: string[] = [];

  questions.push("Will this be a personal project or shared with others?");

  if (services.some((s) => s.name === "S3")) {
    questions.push("How large are the files you plan to upload? (affects storage cost estimate)");
    questions.push("Should uploaded files be publicly accessible or kept private?");
  }

  if (services.some((s) => s.name === "Lambda")) {
    questions.push("How often will this function be invoked? (helps with cost projection)");
    questions.push("Does the function need to access the internet or only other AWS services?");
  }

  if (services.some((s) => s.name === "DynamoDB" || s.name === "RDS")) {
    questions.push("What data do you need to store? (helps design the table or schema)");
    questions.push("Do you need to query by multiple fields, or primarily by a unique ID?");
  }

  if (lower.includes("auth") || lower.includes("user") || lower.includes("login")) {
    questions.push("Do you need social login (Google/GitHub) or just email and password?");
  }

  if (services.some((s) => s.name === "Bedrock" || s.name === "SageMaker")) {
    questions.push("Which AI model do you want to use? Different models have different costs.");
    questions.push("Have you set a spending limit in AWS Budgets before enabling AI features?");
  }

  questions.push("Do you already have an AWS account? (free tier is strongly recommended for beginners)");
  questions.push("What is your target timeline — a weekend project or a multi-week build?");

  return questions.slice(0, 6);
}

/** Step 4: Generate beginner-friendly architecture. */
export function generateArchitecture(
  _idea: string,
  services: DetectedService[],
  skillLevel: SkillLevel,
  budget: BudgetRisk
): ArchitectureSection {
  const serviceNames = services.map((s) => s.awsName).join(", ");
  const isServerless =
    services.some((s) => s.name === "Lambda") &&
    !services.some((s) => s.name === "EC2");

  const components: ArchitectureComponent[] = services
    .filter((s) => s.name !== "IAM" && s.name !== "CloudWatch")
    .map((s) => ({
      name: s.name,
      purpose: getServicePurpose(s.name),
      awsService: s.awsName,
      beginner_tip: getBeginnerTip(s.name, skillLevel),
    }));

  const diagram = buildDiagram(services);

  let description = isServerless
    ? `This is a serverless architecture using ${serviceNames}. Serverless means you don't manage any servers — AWS automatically handles scaling, availability, and patching. You only pay for what you actually use, making it ideal for beginners and low-traffic projects.`
    : services.some((s) => s.riskLevel === "high")
    ? `This architecture uses ${serviceNames}. ${
        skillLevel === "complete-beginner"
          ? "⚠️ Warning: EC2 and RDS instances run 24/7 and incur charges even when idle. Consider a serverless alternative using Lambda and DynamoDB instead."
          : "Be aware that EC2/RDS instances accrue charges continuously — even when no requests are being processed."
      }`
    : `This architecture uses ${serviceNames} to build your project.`;

  // $0 budget: Bedrock is optional advanced, not part of the core MVP path
  if (budget === "$0" && services.some((s) => s.name === "Bedrock")) {
    description +=
      " ⚠️ Bedrock is Optional Advanced and is NOT part of the $0 MVP path — it has no free tier and bills per token. Build and validate the core serverless app first. Add Bedrock only after you have AWS Budgets alerts configured, API rate limiting in place, and you are comfortable with the per-token cost model.";
  }

  return { description, components, diagram };
}

function getServicePurpose(serviceName: string): string {
  const purposes: Record<string, string> = {
    Lambda: "Runs your application code without servers — triggered by events like API calls or file uploads",
    S3: "Stores files (images, documents, backups) with virtually unlimited capacity and 11 nines of durability",
    "API Gateway": "Creates HTTP endpoints that trigger your Lambda functions — your app's public front door",
    DynamoDB: "NoSQL database that scales automatically — perfect for key-value and document data",
    RDS: "Relational SQL database — familiar if you know MySQL or PostgreSQL, but runs 24/7",
    EC2: "Virtual machine with full OS control — powerful, but you manage patching and pay 24/7",
    CloudWatch: "Monitors your app — collects logs, metrics, alerts, and dashboards across all services",
    Cognito: "Handles user sign-up, sign-in, and authentication so you don't build it yourself",
    SQS: "Message queue that decouples services and handles traffic bursts gracefully",
    SNS: "Pub/sub messaging — sends notifications to multiple services or via email/SMS",
    CloudFront: "CDN that delivers your content from servers closest to your users — fast and cheap",
    IAM: "Controls who and what can access your AWS resources — the foundation of cloud security",
    Bedrock: "Access foundation AI models (Claude, Titan, Llama) via API — billed per token used",
    SageMaker: "Train and deploy custom ML models — powerful but complex and expensive for beginners",
    "Step Functions": "Orchestrates multi-step workflows as visual state machines",
    Amplify: "Hosts and deploys web/mobile frontends with built-in CI/CD",
  };
  return purposes[serviceName] ?? `Provides ${serviceName} capabilities for your project`;
}

function getBeginnerTip(serviceName: string, _skillLevel: SkillLevel): string {
  const tips: Record<string, string> = {
    Lambda:
      "Set memory to 128 MB and timeout to 10 seconds. Add a CloudWatch log retention policy of 7 days to avoid log storage charges.",
    S3: "Always enable Block Public Access on every bucket. Use pre-signed URLs for user uploads. Test with small files first.",
    "API Gateway":
      "Use HTTP API (not REST API) — it is simpler and cheaper. Enable CORS only for your specific frontend domain.",
    DynamoDB:
      "Start with on-demand billing mode — you only pay per request with no capacity planning needed.",
    RDS: "⚠️ HIGH RISK for beginners: instances run 24/7. Consider DynamoDB instead unless you specifically need SQL.",
    EC2: "⚠️ HIGH RISK: EC2 instances incur charges even when stopped. Always terminate (not just stop) instances you no longer need.",
    CloudWatch:
      "Set a log retention policy on every Lambda log group — the default is never expire, which will cost money over time.",
    Cognito: "Use the hosted UI to avoid building login screens from scratch. Stick within the 50K MAU free tier.",
    SQS: "Start with a Standard queue. Configure a dead-letter queue to catch and inspect failed messages.",
    SNS: "Avoid SMS notifications during early testing — each message costs ~$0.0075 in the US.",
    CloudFront: "Use the default cache behavior first. Invalidations cost $0.005 each after the first 1,000/month.",
    IAM: "Never use root account credentials for day-to-day work. Create an IAM user with least-privilege policies.",
    Bedrock: "⚠️ BILLED PER TOKEN (no free tier): Set a Budget alert before testing. Start with smaller models like Claude Haiku.",
    SageMaker: "⚠️ EXPENSIVE: Notebook instances and endpoints run continuously. Shut them down the moment you finish.",
    "Step Functions": "Use Express Workflows for high-volume tasks, Standard Workflows for long-running processes.",
    Amplify: "Connect your GitHub repo for automatic deployments. The free tier covers most small projects easily.",
  };
  return tips[serviceName] ?? `Follow AWS Well-Architected Framework principles when configuring ${serviceName}.`;
}

function buildDiagram(services: DetectedService[]): string {
  const names = services
    .filter((s) => s.name !== "IAM" && s.name !== "CloudWatch")
    .map((s) => s.name);

  if (names.length === 0) return "";

  const hasApiGateway = names.includes("API Gateway");
  const hasLambda = names.includes("Lambda");
  const hasS3 = names.includes("S3");
  const hasDynamo = names.includes("DynamoDB");
  const hasRDS = names.includes("RDS");
  const hasCognito = names.includes("Cognito");
  const hasCloudFront = names.includes("CloudFront");

  let d = "";
  d += "  User / Browser / Client\n";
  d += "        │\n";

  if (hasCognito) {
    d += "        ├──── Cognito (Auth)\n";
    d += "        │\n";
  }

  if (hasCloudFront) {
    d += "        ▼\n";
    d += "  ┌─────────────────────┐\n";
    d += "  │     CloudFront      │  ← CDN / edge cache\n";
    d += "  └─────────┬───────────┘\n";
  }

  d += "        │\n";
  d += "        ▼\n";

  if (hasApiGateway) {
    d += "  ┌─────────────────────┐\n";
    d += "  │    API Gateway      │  ← HTTPS endpoint\n";
    d += "  └─────────┬───────────┘\n";
    d += "            │\n";
    d += "            ▼\n";
  } else if (hasLambda) {
    d += "  ┌─────────────────────┐\n";
    d += "  │  Lambda Function URL│  ← HTTPS endpoint (free, no API Gateway)\n";
    d += "  └─────────┬───────────┘\n";
    d += "            │\n";
    d += "            ▼\n";
  }

  if (hasLambda) {
    d += "  ┌─────────────────────┐\n";
    d += "  │   Lambda Function   │  ← Your business logic\n";

    const storageTargets: string[] = [];
    if (hasDynamo) storageTargets.push("DynamoDB");
    if (hasRDS) storageTargets.push("RDS");
    if (hasS3) storageTargets.push("S3");

    if (storageTargets.length > 0) {
      d += "  └──┬──────────────────┘\n";
      d += "     │\n";
      d += `     ├── ${storageTargets.join("  │  ")}\n`;
    } else {
      d += "  └─────────────────────┘\n";
    }
  }

  d += "\n";
  d += "  ─────────────────────────────────────\n";
  d += "  CloudWatch — logs & metrics (all svcs)\n";
  d += "  IAM        — access control (all svcs)\n";

  return d;
}

/** Step 5: Generate security review with always-on safety warnings. */
export function generateSecurityReview(
  services: DetectedService[],
  _skillLevel: SkillLevel
): SecurityReview {
  const warnings: SecurityWarning[] = [];
  const iamRecommendations: string[] = [];
  const bestPractices: string[] = [];

  // Universal critical warnings — always shown
  warnings.push({
    level: "critical",
    title: "Never use AdministratorAccess IAM policies",
    description:
      "AdministratorAccess grants unrestricted control over your entire AWS account. If a credential is leaked, attackers can spin up expensive resources or exfiltrate data. Always create fine-grained policies that allow only the exact actions your application needs.",
  });

  warnings.push({
    level: "critical",
    title: "Never hardcode AWS credentials in your code",
    description:
      "Do not put AWS_ACCESS_KEY_ID or AWS_SECRET_ACCESS_KEY in code, .env files committed to Git, or any frontend JavaScript. Use IAM roles for Lambda and EC2, environment variables injected at deploy time, or AWS Secrets Manager for all credentials.",
  });

  warnings.push({
    level: "warning",
    title: "Set up AWS Budgets immediately — before you deploy anything",
    description:
      "Go to AWS Console → Billing and Cost Management → Budgets → Create budget → Zero spend budget. Enter your email and save. You will receive an email the moment any charge appears. This is the single most effective safeguard against unexpected bills for beginners.",
  });

  // S3 warnings
  if (services.some((s) => s.name === "S3")) {
    warnings.push({
      level: "critical",
      title: "Always block public access on S3 buckets",
      description:
        "Public S3 buckets have exposed sensitive data at major companies. Enable 'Block Public Access' on every bucket you create. Use pre-signed URLs (set to expire in 15 minutes) to let users securely upload or download files without exposing the bucket.",
    });
    iamRecommendations.push(
      "Grant Lambda only s3:GetObject and s3:PutObject on the specific bucket ARN — never s3:* on *"
    );
    iamRecommendations.push("Enable S3 server-side encryption (SSE-S3 is free) on all buckets");
  }

  // Lambda warnings
  if (services.some((s) => s.name === "Lambda")) {
    warnings.push({
      level: "info",
      title: "Use least-privilege IAM roles for each Lambda function",
      description:
        "Create a dedicated IAM execution role for each Lambda function and grant only the specific permissions that function needs. Use resource-level permissions with specific ARNs rather than wildcards.",
    });
    iamRecommendations.push("Set Lambda reserved concurrency to 10 initially to prevent runaway invocations");
    iamRecommendations.push("Set CloudWatch log retention to 7 days on every Lambda log group");
  }

  // API Gateway warnings
  if (services.some((s) => s.name === "API Gateway")) {
    warnings.push({
      level: "warning",
      title: "Enable API throttling on API Gateway",
      description:
        "Without throttling, a bot or a runaway loop could invoke your Lambda thousands of times per second, generating a large bill. Set a rate limit (e.g. 100 requests/second) and burst limit in the API Gateway stage settings.",
    });
    iamRecommendations.push("Enable access logging for API Gateway to CloudWatch for audit trails");
  }

  // Lambda Function URL throttle reminder (when Lambda present but no API Gateway)
  if (services.some((s) => s.name === "Lambda") && !services.some((s) => s.name === "API Gateway")) {
    warnings.push({
      level: "warning",
      title: "Set Lambda reserved concurrency when using Function URLs",
      description:
        "Lambda Function URLs have no built-in throttling. Set a reserved concurrency limit (start with 10) on your function to cap maximum parallel invocations and prevent runaway billing from bots or loops.",
    });
  }

  // EC2 / RDS warnings
  if (services.some((s) => s.name === "EC2" || s.name === "RDS")) {
    warnings.push({
      level: "critical",
      title: "Restrict Security Groups — never open to 0.0.0.0/0",
      description:
        "Never open SSH (port 22) or database ports (3306, 5432) to the entire internet (0.0.0.0/0). Restrict inbound rules to your specific IP address, or better yet, use AWS Systems Manager Session Manager instead of SSH entirely.",
    });
    if (services.some((s) => s.name === "RDS")) {
      iamRecommendations.push("Use RDS IAM database authentication instead of password-based auth");
    }
  }

  // Cognito warnings
  if (services.some((s) => s.name === "Cognito")) {
    warnings.push({
      level: "info",
      title: "Enable MFA for production Cognito user pools",
      description:
        "Multi-factor authentication significantly reduces account takeover risk. Enable optional or required MFA for any user pool that handles real user accounts.",
    });
  }

  // Bedrock / SageMaker warnings
  if (services.some((s) => s.name === "Bedrock")) {
    warnings.push({
      level: "critical",
      title: "Bedrock has no free tier — set spending limits before testing",
      description:
        "Amazon Bedrock charges per input and output token with no free tier. A runaway loop or an unguarded public endpoint can generate hundreds of dollars in charges very quickly. Always set an AWS Budget alert before enabling Bedrock. Never expose a Bedrock endpoint directly to end users without rate limiting.",
    });
  }

  if (services.some((s) => s.name === "SageMaker")) {
    warnings.push({
      level: "critical",
      title: "SageMaker endpoints and notebook instances run 24/7",
      description:
        "SageMaker instances and endpoints accrue charges every hour they are running, even with zero traffic. Always stop notebook instances and delete endpoints immediately when not in use. Use lifecycle configurations to auto-stop idle notebooks.",
    });
  }

  // Universal best practices
  bestPractices.push("Enable AWS CloudTrail to log every API call across your account for security audits");
  bestPractices.push("Tag all resources with Environment=dev and Project=<name> for easy cost tracking and cleanup");
  bestPractices.push("Use AWS Secrets Manager or SSM Parameter Store for database passwords and third-party API keys");
  bestPractices.push("Enable MFA on your AWS root account and lock the root credentials in a password manager");
  bestPractices.push("Use the principle of least privilege: grant only the minimum permissions required for each resource");
  bestPractices.push("Enable versioning on S3 buckets storing important data to protect against accidental deletion");
  bestPractices.push("Prefer IAM Identity Center (SSO) or AWS CloudShell over long-term IAM access keys");
  bestPractices.push("Review your AWS Trusted Advisor recommendations monthly — the free tier covers security checks");

  return { warnings, iamRecommendations, bestPractices };
}

/** Step 6: Generate cost and free-tier review. */
export function generateCostReview(
  services: DetectedService[],
  budget: BudgetRisk
): CostReview {
  const freetiierItems: CostItem[] = [];
  const paidRisks: CostItem[] = [];

  interface CostEntry {
    free: string;
    risk: string;
    riskLevel: "free" | "low" | "medium" | "high";
  }

  const costMap: Record<string, CostEntry> = {
    Lambda: {
      free: "1M requests + 400,000 GB-seconds/month free forever",
      risk: "Negligible for hobby projects — you pay only above 1M invocations/month",
      riskLevel: "free",
    },
    "API Gateway": {
      free: "1M HTTP API calls/month free for 12 months",
      risk: "$1.00 per million calls after the free tier expires",
      riskLevel: "low",
    },
    S3: {
      free: "5 GB storage + 20K GET + 2K PUT requests free for 12 months",
      risk: "Watch for data transfer out charges ($0.09/GB after the first 1 GB/month) — large file downloads add up",
      riskLevel: "low",
    },
    DynamoDB: {
      free: "25 GB storage + 25 RCU + 25 WCU free forever (on-demand mode costs more per request)",
      risk: "Low risk for dev workloads — use on-demand billing and stay within the free tier",
      riskLevel: "low",
    },
    RDS: {
      free: "750 hours/month db.t2.micro free for 12 months only",
      risk: "⚠️ After 12 months or with larger instances: $15–$50/month. Instances charge 24/7 even when idle.",
      riskLevel: "high",
    },
    EC2: {
      free: "750 hours/month t2.micro free for 12 months only",
      risk: "⚠️ After 12 months: ~$8–$10/month for a t2.micro running 24/7. A t3.medium runs ~$30/month.",
      riskLevel: "high",
    },
    CloudWatch: {
      free: "10 custom metrics + 10 alarms + 5 GB log ingestion + 5 GB log storage free",
      risk: "Log storage accumulates over time — set 7-day retention on all Lambda log groups",
      riskLevel: "low",
    },
    Cognito: {
      free: "50,000 monthly active users (MAUs) free forever",
      risk: "$0.0055 per MAU above 50K — unlikely to hit this limit for most beginner projects",
      riskLevel: "free",
    },
    SQS: {
      free: "1M requests/month free forever",
      risk: "Negligible — $0.40 per million requests above the free tier",
      riskLevel: "free",
    },
    SNS: {
      free: "1M publishes + 100K HTTP deliveries free forever",
      risk: "SMS charges apply immediately: ~$0.0075 per message in the US — avoid during testing",
      riskLevel: "low",
    },
    CloudFront: {
      free: "1 TB data out + 10M HTTP/HTTPS requests free for 12 months",
      risk: "Low after free tier — $0.0085/GB data transfer. Cache invalidations: $0.005 each after first 1,000",
      riskLevel: "low",
    },
    IAM: {
      free: "Always free — no charge for IAM users, roles, or policies",
      risk: "No cost",
      riskLevel: "free",
    },
    Bedrock: {
      free: "No free tier",
      risk: "⚠️ Billed per token. Claude Haiku: ~$0.00025/1K input + $0.00125/1K output tokens. Easy to spend $10–$50 in initial testing.",
      riskLevel: "high",
    },
    SageMaker: {
      free: "2-month free trial for limited instance types only",
      risk: "⚠️ Notebook instances + endpoints charge $0.10–$3.00/hour. Forgetting to stop = significant bill.",
      riskLevel: "high",
    },
    "Step Functions": {
      free: "4,000 state transitions/month free forever",
      risk: "Low — $0.025 per 1,000 state transitions above the free tier",
      riskLevel: "free",
    },
    Amplify: {
      free: "15 GB/month + 1,000 build minutes free for 12 months",
      risk: "$0.01 per build minute + $0.15/GB served after free tier",
      riskLevel: "low",
    },
  };

  for (const svc of services) {
    const info = costMap[svc.name];
    if (!info) continue;

    // For $0 budget, treat Bedrock as Optional Advanced — not a paid risk in the MVP path
    if (budget === "$0" && svc.name === "Bedrock") {
      freetiierItems.push({
        service: svc.awsName,
        detail:
          "Optional Advanced / High Risk — NOT in the $0 MVP path. No free tier. Add only after AWS Budgets alerts and Lambda concurrency limits are configured.",
        risk: "low",
      });
      continue;
    }

    if (info.riskLevel === "free" || info.riskLevel === "low") {
      freetiierItems.push({ service: svc.awsName, detail: info.free, risk: info.riskLevel });
    } else {
      paidRisks.push({ service: svc.awsName, detail: info.risk, risk: info.riskLevel });
    }
  }

  const hasHighRisk = paidRisks.length > 0;
  const highRiskNames = services
    .filter((s) => s.riskLevel === "high" && s.name !== "Bedrock")
    .map((s) => s.name);

  let budgetAdvice = "";
  if (budget === "$0") {
    budgetAdvice =
      "For a true $0/month budget: build with Lambda + DynamoDB + S3. Use Lambda Function URLs instead of API Gateway to stay free after the 12-month API Gateway free tier expires. These services have perpetual free tiers sufficient for most hobby projects. Avoid EC2, RDS, and SageMaker. Bedrock can be added later — only after AWS Budgets alerts and Lambda concurrency limits are in place.";
    if (highRiskNames.length > 0) {
      budgetAdvice += ` ⚠️ Your plan includes ${highRiskNames.join(", ")} which can exceed $0. Consider serverless alternatives.`;
    }
  } else if (budget === "$1") {
    budgetAdvice = `With a $1/month budget, serverless services (Lambda, API Gateway, DynamoDB) will keep costs near zero in the free tier. Set a $1 AWS Budget alert immediately (Console → Billing → Budgets → Zero spend budget). Avoid EC2 and RDS which charge continuously even at idle.`;
  } else if (budget === "$5") {
    budgetAdvice = `$5/month gives comfortable headroom for serverless workloads plus occasional S3 data transfer. You could add CloudFront within this budget for a small number of users. Set a $5 Budget alert (Console → Billing → Budgets).`;
  } else {
    budgetAdvice = `$10/month opens more options: a t2.micro EC2 or RDS instance for ~2 weeks/month, or moderate serverless traffic. Set a $10 Budget alert (Console → Billing → Budgets) and review Cost Explorer weekly to catch surprises early.`;
  }

  const estimatedMonthly = hasHighRisk
    ? "$5–$50+ per month (depending on usage and free tier status)"
    : "$0–$2 per month (mostly within free tier)";

  return { estimatedMonthly, freetiierItems, paidRisks, budgetAdvice };
}

/** Step 7: Generate step-by-step implementation guide. */
export function generateSteps(
  _idea: string,
  services: DetectedService[],
  region: string,
  _skillLevel: SkillLevel
): Step[] {
  const steps: Step[] = [];
  let stepNum = 1;

  const hasLambda = services.some((s) => s.name === "Lambda");
  const hasApiGateway = services.some((s) => s.name === "API Gateway");

  // Step 1: Secure your AWS account + set budget alert
  steps.push({
    number: stepNum++,
    title: "Secure your AWS account before deploying anything",
    description:
      "Follow these steps in the AWS Console. No CLI needed yet. This prevents accidental charges and the security incidents that are most common for beginners.",
    commands: [
      "# ── 1. Enable MFA on your root account ───────────────────────────────",
      "# AWS Console → click your account name (top right) → Security credentials",
      "# → Multi-factor authentication (MFA) → Assign MFA device",
      "# Use an authenticator app (Google Authenticator, 1Password, etc.)",
      "",
      "# ── 2. Create a day-to-day IAM user (never use root for daily work) ──",
      "# AWS Console → IAM → Users → Create user",
      "# Attach a least-privilege policy (e.g. PowerUserAccess for learning labs)",
      "",
      "# ── 3. Set a Zero Spend Budget alert (do this NOW, before any deployments) ──",
      "# AWS Console → Billing and Cost Management → Budgets",
      "#   → Create budget → Zero spend budget → enter your email → Create budget",
      "# You will receive an email the moment any charge appears on your account.",
      "",
      "# ── Advanced CLI budget option (budget JSON is error-prone — prefer Console above) ──",
      `# ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)`,
      `# aws budgets create-budget --account-id $ACCOUNT_ID \\`,
      `#   --budget '{"BudgetName":"lab-zero-spend","BudgetLimit":{"Amount":"1","Unit":"USD"},"TimeUnit":"MONTHLY","BudgetType":"COST"}' \\`,
      `#   --notifications-with-subscribers '[{"Notification":{"NotificationType":"ACTUAL","ComparisonOperator":"GREATER_THAN","Threshold":1},"Subscribers":[{"SubscriptionType":"EMAIL","Address":"your@email.com"}]}]'`,
    ],
    consoleLink: `https://console.aws.amazon.com/billing/home#/budgets/create`,
  });

  // Step 2: Get access to the AWS CLI
  steps.push({
    number: stepNum++,
    title: "Get access to the AWS CLI",
    description:
      "Recommended for beginners: use AWS CloudShell in your browser — no install or credential setup needed. It has the latest AWS CLI pre-installed and uses your console session.",
    commands: [
      "# ── Recommended: AWS CloudShell (no install or credentials needed) ──────",
      "# AWS Console → top navigation bar → CloudShell icon [>_]",
      "# CloudShell opens a terminal with the AWS CLI already configured.",
      "# Use it for all CLI commands in this guide without any local setup.",
      "",
      "# ── If you prefer a local CLI install ───────────────────────────────────",
      "",
      "# macOS",
      "brew install awscli",
      "",
      "# Linux",
      `curl 'https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip' -o awscliv2.zip`,
      `unzip awscliv2.zip && sudo ./aws/install`,
      "",
      "# Windows: download the MSI installer from https://aws.amazon.com/cli/",
      "",
      "# ── Preferred credential method: IAM Identity Center (SSO) ─────────────",
      "# Provides short-lived temporary credentials — much safer than long-term keys",
      `aws configure sso`,
      `# → Follow the browser prompt to sign in`,
      "",
      "# ── ⚠️  Advanced local option: long-term access keys (not recommended) ──",
      "# Risk: long-term keys in config files can be accidentally committed to Git.",
      "# Use CloudShell or IAM Identity Center instead whenever possible.",
      `# aws configure`,
      `# → AWS Access Key ID:     <paste key>`,
      `# → AWS Secret Access Key: <paste secret>`,
      `# → Default region name:   ${region}`,
      `# → Default output format: json`,
      "",
      "# Verify your credentials are working",
      `aws sts get-caller-identity`,
    ],
  });

  // Lambda setup
  if (hasLambda) {
    steps.push({
      number: stepNum++,
      title: "Create your Lambda function with a least-privilege IAM role",
      description:
        "Lambda runs your code on demand. Use 128 MB memory and a short timeout to stay within the free tier.",
      commands: [
        "# Create IAM execution role for Lambda",
        `aws iam create-role \\`,
        `  --role-name lab-lambda-role \\`,
        `  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'`,
        "",
        "# Attach only the minimal CloudWatch Logs permission",
        `aws iam attach-role-policy \\`,
        `  --role-name lab-lambda-role \\`,
        `  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole`,
        "",
        "# Package your code",
        `zip function.zip index.js  # or handler.py for Python`,
        "",
        "# Create the function",
        `ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)`,
        `aws lambda create-function \\`,
        `  --function-name my-lab-function \\`,
        `  --runtime nodejs20.x \\`,
        `  --role arn:aws:iam::$ACCOUNT_ID:role/lab-lambda-role \\`,
        `  --handler index.handler \\`,
        `  --memory-size 128 \\`,
        `  --timeout 10 \\`,
        `  --zip-file fileb://function.zip \\`,
        `  --region ${region}`,
        "",
        "# ⚠️ Set log retention to 7 days (prevents log storage costs)",
        `aws logs put-retention-policy \\`,
        `  --log-group-name /aws/lambda/my-lab-function \\`,
        `  --retention-in-days 7 \\`,
        `  --region ${region}`,
        "",
        "# ⚠️ Set reserved concurrency to cap parallel invocations (prevents runaway billing)",
        `aws lambda put-function-concurrency \\`,
        `  --function-name my-lab-function \\`,
        `  --reserved-concurrent-executions 10 \\`,
        `  --region ${region}`,
      ],
      consoleLink: `https://${region}.console.aws.amazon.com/lambda/home`,
    });

    // Lambda Function URL setup — when API Gateway is NOT selected
    if (!hasApiGateway) {
      steps.push({
        number: stepNum++,
        title: "Add a Lambda Function URL (free HTTPS endpoint — no API Gateway needed)",
        description:
          "Lambda Function URLs give your function a public HTTPS endpoint without API Gateway. They are always free and simpler to configure. Use them for $0 budget architectures.",
        commands: [
          "# Create a public Function URL (auth type NONE — protect with Lambda logic or a secret header)",
          `aws lambda create-function-url-config \\`,
          `  --function-name my-lab-function \\`,
          `  --auth-type NONE \\`,
          `  --region ${region}`,
          "",
          "# Grant public invoke permission for the Function URL",
          `aws lambda add-permission \\`,
          `  --function-name my-lab-function \\`,
          `  --statement-id FunctionURLAllowPublicAccess \\`,
          `  --action lambda:InvokeFunctionUrl \\`,
          `  --principal '*' \\`,
          `  --function-url-auth-type NONE \\`,
          `  --region ${region}`,
          "",
          "# Get your Function URL",
          `aws lambda get-function-url-config \\`,
          `  --function-name my-lab-function \\`,
          `  --query FunctionUrl \\`,
          `  --output text \\`,
          `  --region ${region}`,
          "",
          "# Test it",
          `curl $(aws lambda get-function-url-config --function-name my-lab-function --query FunctionUrl --output text --region ${region})`,
        ],
        consoleLink: `https://${region}.console.aws.amazon.com/lambda/home`,
      });
    }
  }

  // S3 setup
  if (services.some((s) => s.name === "S3")) {
    steps.push({
      number: stepNum++,
      title: "Create a private S3 bucket with Block Public Access enabled",
      description:
        "Always block public access on every S3 bucket. Use pre-signed URLs to let users upload or download files securely.",
      commands: [
        "# Create bucket (names must be globally unique — the timestamp makes yours unique)",
        `BUCKET_NAME=my-lab-bucket-$(date +%s)`,
        `aws s3api create-bucket \\`,
        `  --bucket $BUCKET_NAME \\`,
        `  --region ${region}${region !== "us-east-1" ? ` \\\n  --create-bucket-configuration LocationConstraint=${region}` : ""}`,
        "",
        "# ⚠️ Block ALL public access (critical — do this immediately after creation)",
        `aws s3api put-public-access-block \\`,
        `  --bucket $BUCKET_NAME \\`,
        `  --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"`,
        "",
        "# Enable server-side encryption (free)",
        `aws s3api put-bucket-encryption \\`,
        `  --bucket $BUCKET_NAME \\`,
        `  --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'`,
        "",
        "# Test with a small file",
        `echo 'hello world' > test.txt`,
        `aws s3 cp test.txt s3://$BUCKET_NAME/test.txt`,
        `aws s3 ls s3://$BUCKET_NAME`,
        `rm test.txt`,
      ],
      consoleLink: `https://s3.console.aws.amazon.com/s3/home?region=${region}`,
    });
  }

  // API Gateway setup
  if (hasApiGateway) {
    steps.push({
      number: stepNum++,
      title: "Create an HTTP API with API Gateway and add throttling",
      description:
        "HTTP API is simpler and cheaper than REST API. Always configure throttling to protect against runaway invocations.",
      commands: [
        "# Create the HTTP API",
        `API_ID=$(aws apigatewayv2 create-api \\`,
        `  --name my-lab-api \\`,
        `  --protocol-type HTTP \\`,
        `  --region ${region} \\`,
        `  --query ApiId --output text)`,
        `echo "API ID: $API_ID"`,
        "",
        "# Create Lambda integration",
        `ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)`,
        `INTEGRATION_ID=$(aws apigatewayv2 create-integration \\`,
        `  --api-id $API_ID \\`,
        `  --integration-type AWS_PROXY \\`,
        `  --integration-uri arn:aws:apigateway:${region}:lambda:path/2015-03-31/functions/arn:aws:lambda:${region}:$ACCOUNT_ID:function:my-lab-function/invocations \\`,
        `  --payload-format-version 2.0 \\`,
        `  --query IntegrationId --output text)`,
        "",
        "# Add a catch-all route",
        `aws apigatewayv2 create-route \\`,
        `  --api-id $API_ID \\`,
        `  --route-key 'ANY /{proxy+}' \\`,
        `  --target integrations/$INTEGRATION_ID`,
        "",
        "# Deploy with throttling (rate and burst limits protect against runaway costs)",
        `aws apigatewayv2 create-stage \\`,
        `  --api-id $API_ID \\`,
        `  --stage-name dev \\`,
        `  --auto-deploy \\`,
        `  --default-route-settings '{"ThrottlingBurstLimit":10,"ThrottlingRateLimit":20}'`,
        "",
        "# Grant API Gateway permission to invoke Lambda",
        `aws lambda add-permission \\`,
        `  --function-name my-lab-function \\`,
        `  --statement-id api-gateway-invoke \\`,
        `  --action lambda:InvokeFunction \\`,
        `  --principal apigateway.amazonaws.com`,
        "",
        "# Print and test your endpoint",
        `echo "https://$API_ID.execute-api.${region}.amazonaws.com/dev/"`,
        `curl "https://$API_ID.execute-api.${region}.amazonaws.com/dev/"`,
      ],
      consoleLink: `https://${region}.console.aws.amazon.com/apigateway/home`,
    });
  }

  // DynamoDB setup
  if (services.some((s) => s.name === "DynamoDB")) {
    steps.push({
      number: stepNum++,
      title: "Create a DynamoDB table with on-demand billing",
      description:
        "DynamoDB is a serverless NoSQL database. On-demand billing means you pay per request — no capacity planning required.",
      commands: [
        "# Create table with on-demand billing (recommended for beginners)",
        `aws dynamodb create-table \\`,
        `  --table-name my-lab-table \\`,
        `  --attribute-definitions AttributeName=id,AttributeType=S \\`,
        `  --key-schema AttributeName=id,KeyType=HASH \\`,
        `  --billing-mode PAY_PER_REQUEST \\`,
        `  --region ${region}`,
        "",
        "# Wait for table to become ACTIVE",
        `aws dynamodb wait table-exists --table-name my-lab-table --region ${region}`,
        `echo "Table is ready!"`,
        "",
        "# Test: insert an item",
        `aws dynamodb put-item \\`,
        `  --table-name my-lab-table \\`,
        `  --item '{"id":{"S":"test-1"},"message":{"S":"Hello DynamoDB!"}}' \\`,
        `  --region ${region}`,
        "",
        "# Test: read the item back",
        `aws dynamodb get-item \\`,
        `  --table-name my-lab-table \\`,
        `  --key '{"id":{"S":"test-1"}}' \\`,
        `  --region ${region}`,
      ],
      consoleLink: `https://${region}.console.aws.amazon.com/dynamodbv2/home`,
    });
  }

  // Verification step — always last
  steps.push({
    number: stepNum++,
    title: "Verify your setup and check for unexpected charges",
    description:
      "Test the full flow before adding more complexity. Check CloudWatch Logs for errors and Cost Explorer for any unexpected charges.",
    commands: [
      "# List your Lambda functions",
      `aws lambda list-functions --region ${region} --query 'Functions[].FunctionName'`,
      "",
      "# Tail CloudWatch Logs for your function (Ctrl+C to stop)",
      `aws logs tail /aws/lambda/my-lab-function --follow --region ${region}`,
      "",
      "# Check recent costs (takes ~24 hours to appear in Cost Explorer)",
      `aws ce get-cost-and-usage \\`,
      `  --time-period Start=$(date -d '7 days ago' +%Y-%m-%d 2>/dev/null || date -v-7d +%Y-%m-%d),End=$(date +%Y-%m-%d) \\`,
      `  --granularity DAILY \\`,
      `  --metrics BlendedCost \\`,
      `  --query 'ResultsByTime[*].{Date:TimePeriod.Start,Cost:Total.BlendedCost.Amount}'`,
    ],
    consoleLink: `https://${region}.console.aws.amazon.com/cloudwatch/home`,
  });

  return steps;
}

/** Step 8: Generate cleanup checklist and commands. */
export function generateCleanup(services: DetectedService[], region: string): CleanupSection {
  const checklist: string[] = [];
  const commands: string[] = [];

  const hasLambda = services.some((s) => s.name === "Lambda");
  const hasApiGateway = services.some((s) => s.name === "API Gateway");

  if (hasLambda) {
    checklist.push("[ ] Delete all Lambda functions created for this lab");
  }
  if (hasApiGateway) {
    checklist.push("[ ] Delete API Gateway APIs");
  } else if (hasLambda) {
    checklist.push("[ ] Remove Lambda Function URL config (if configured)");
  }
  if (services.some((s) => s.name === "S3")) {
    checklist.push("[ ] Empty then delete S3 buckets (buckets must be empty before deletion)");
  }
  if (services.some((s) => s.name === "DynamoDB")) {
    checklist.push("[ ] Delete DynamoDB tables");
  }
  checklist.push("[ ] Detach policies and delete IAM roles created for this lab");
  checklist.push("[ ] Delete CloudWatch Log Groups — check /aws/lambda/* prefix");
  checklist.push("[ ] Verify $0 balance in AWS Cost Explorer after cleanup (allow 24 hours)");
  checklist.push("[ ] Review your AWS Budget alerts — remove if no longer needed");

  if (services.some((s) => s.name === "EC2")) {
    checklist.push("[ ] TERMINATE (not stop) all EC2 instances — stopped instances still charge for EBS storage");
    checklist.push("[ ] Release Elastic IPs — unreleased EIPs cost $0.005/hr when not attached to a running instance");
    checklist.push("[ ] Delete EBS volumes — orphaned volumes continue to incur storage charges");
  }

  if (services.some((s) => s.name === "RDS")) {
    checklist.push("[ ] Delete RDS instances — take a final snapshot first if you need the data");
    checklist.push("[ ] Delete automated backups and manual snapshots");
    checklist.push("[ ] Delete the RDS subnet group");
  }

  if (services.some((s) => s.name === "CloudFront")) {
    checklist.push("[ ] Disable CloudFront distributions first, then delete them (disabling takes ~15 minutes)");
  }

  if (services.some((s) => s.name === "Cognito")) {
    checklist.push("[ ] Delete Cognito User Pools and Identity Pools");
  }

  if (services.some((s) => s.name === "SageMaker")) {
    checklist.push("[ ] STOP SageMaker notebook instances — running instances charge by the hour");
    checklist.push("[ ] DELETE SageMaker endpoints — endpoints charge even with zero traffic");
    checklist.push("[ ] Delete SageMaker models and training jobs");
  }

  // CLI commands
  if (hasLambda) {
    commands.push(`# ─── Lambda ───────────────────────────────────────────────`);
    commands.push(`aws lambda delete-function \\`);
    commands.push(`  --function-name my-lab-function \\`);
    commands.push(`  --region ${region}`);
    commands.push(``);
  }

  if (hasApiGateway) {
    commands.push(`# ─── API Gateway ──────────────────────────────────────────`);
    commands.push(`aws apigatewayv2 delete-api \\`);
    commands.push(`  --api-id YOUR_API_ID \\`);
    commands.push(`  --region ${region}`);
    commands.push(``);
  } else if (hasLambda) {
    commands.push(`# ─── Lambda Function URL (remove if configured) ──────────`);
    commands.push(`aws lambda delete-function-url-config \\`);
    commands.push(`  --function-name my-lab-function \\`);
    commands.push(`  --region ${region}`);
    commands.push(``);
  }

  if (services.some((s) => s.name === "S3")) {
    commands.push(`# ─── S3 (must empty bucket before deleting) ───────────────`);
    commands.push(`aws s3 rm s3://YOUR_BUCKET_NAME --recursive`);
    commands.push(`aws s3api delete-bucket \\`);
    commands.push(`  --bucket YOUR_BUCKET_NAME \\`);
    commands.push(`  --region ${region}`);
    commands.push(``);
  }

  if (services.some((s) => s.name === "DynamoDB")) {
    commands.push(`# ─── DynamoDB ─────────────────────────────────────────────`);
    commands.push(`aws dynamodb delete-table \\`);
    commands.push(`  --table-name my-lab-table \\`);
    commands.push(`  --region ${region}`);
    commands.push(``);
  }

  commands.push(`# ─── CloudWatch Logs ──────────────────────────────────────`);
  commands.push(`aws logs delete-log-group \\`);
  commands.push(`  --log-group-name /aws/lambda/my-lab-function \\`);
  commands.push(`  --region ${region}`);
  commands.push(``);
  commands.push(`# ─── IAM (detach policies first, then delete role) ────────`);
  commands.push(`aws iam detach-role-policy \\`);
  commands.push(`  --role-name lab-lambda-role \\`);
  commands.push(`  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole`);
  commands.push(`aws iam delete-role --role-name lab-lambda-role`);
  commands.push(``);
  commands.push(`# ─── Verify no charges (check after 24 hours) ─────────────`);
  commands.push(`aws ce get-cost-and-usage \\`);
  commands.push(`  --time-period Start=$(date -d '1 day ago' +%Y-%m-%d 2>/dev/null || date -v-1d +%Y-%m-%d),End=$(date +%Y-%m-%d) \\`);
  commands.push(`  --granularity DAILY \\`);
  commands.push(`  --metrics UnblendedCost`);

  return { checklist, commands, estimatedTime: "15–30 minutes" };
}

/** Step 9: Generate Portfolio README. */
export function generateReadme(
  idea: string,
  services: DetectedService[],
  plan: Omit<LabPlan, "readme" | "pipelineMode">,
  region: string
): string {
  const serviceList = services
    .map((s) => `- **${s.awsName}** — ${s.freetier}`)
    .join("\n");

  const stepList = plan.steps.map((s) => `${s.number}. ${s.title}`).join("\n");

  const securityHighlights = plan.securityReview.bestPractices
    .slice(0, 5)
    .map((p) => `- ${p}`)
    .join("\n");

  const cleanupCmds = plan.cleanup.commands.slice(0, 14).join("\n");

  return `# ${idea}

> A free-tier-aware AWS lab project with production-safe patterns for beginners.

## What This Project Does

${plan.architecture.description}

## AWS Services Used

${serviceList}

## Architecture Diagram

\`\`\`
${plan.architecture.diagram}
\`\`\`

## Prerequisites

- AWS Account (free tier recommended)
- AWS CLI installed and configured, or use AWS CloudShell (no install needed)
- Target region: \`${region}\`

## Estimated Monthly Cost

**${plan.costReview.estimatedMonthly}**

${plan.costReview.budgetAdvice}

> Set an AWS Budget alert before you start: AWS Console → Billing and Cost Management → Budgets → Create budget → Zero spend budget.

## Implementation Steps

${stepList}

## Security Practices Applied

${securityHighlights}

## Cleanup Instructions

Run these commands when you are finished to avoid ongoing charges.
Estimated time: ${plan.cleanup.estimatedTime}.

\`\`\`bash
${cleanupCmds}
\`\`\`

${plan.cleanup.checklist.map((item) => item).join("\n")}

## What I Learned

- How to use ${services.slice(0, 3).map((s) => s.name).join(", ")} in a real-world scenario
- AWS IAM least-privilege design patterns
- Free-tier cost management and AWS Budgets
- Secure cloud architecture fundamentals for beginners

## References

- [AWS Free Tier](https://aws.amazon.com/free/)
- [AWS Well-Architected Framework](https://aws.amazon.com/architecture/well-architected/)
- [AWS CLI Reference](https://docs.aws.amazon.com/cli/latest/reference/)
- [AWS Pricing Calculator](https://calculator.aws/)
- [AWS Trusted Advisor](https://console.aws.amazon.com/trustedadvisor/)

---

*Generated by [Cloud Lab Guardian](https://github.com/) v0.1.0 — safe, free-tier-aware AWS labs for beginners.*
`;
}

// ---------------------------------------------------------------------------
// Main Pipeline Orchestrator
// ---------------------------------------------------------------------------

export interface PipelineInput {
  idea: string;
  skillLevel: SkillLevel;
  budget: BudgetRisk;
  region: string;
}

/** Run all pipeline stages and return a complete LabPlan. */
export async function runGuardianPipeline(input: PipelineInput): Promise<LabPlan> {
  const { idea, skillLevel, budget, region } = input;

  // Optional: call a Lambda Function URL if LAB_GUARDIAN_API_URL is configured
  const lambdaUrl = import.meta.env?.LAB_GUARDIAN_API_URL as string | undefined;
  if (lambdaUrl) {
    try {
      const res = await fetch(lambdaUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(input),
      });
      if (res.ok) {
        const data = await res.json() as Omit<LabPlan, "pipelineMode">;
        return { ...data, pipelineMode: "lambda" };
      }
    } catch {
      console.warn("LAB_GUARDIAN_API_URL call failed — falling back to local pipeline");
    }
  }

  const pipelineMode: PipelineMode = lambdaUrl ? "lambda-fallback" : "local";

  // Deterministic local pipeline
  const normalizedIdea = normalizeUserIdea(idea);
  const detectedServices = detectServices(normalizedIdea);
  const clarifyingQuestions = generateClarifyingQuestions(normalizedIdea, detectedServices);
  const architecture = generateArchitecture(normalizedIdea, detectedServices, skillLevel, budget);
  const securityReview = generateSecurityReview(detectedServices, skillLevel);
  const costReview = generateCostReview(detectedServices, budget);
  const steps = generateSteps(normalizedIdea, detectedServices, region, skillLevel);
  const cleanup = generateCleanup(detectedServices, region);

  const partial: Omit<LabPlan, "readme" | "pipelineMode"> = {
    normalizedIdea,
    detectedServices,
    clarifyingQuestions,
    architecture,
    securityReview,
    costReview,
    steps,
    cleanup,
  };

  const readme = generateReadme(normalizedIdea, detectedServices, partial, region);

  return { ...partial, readme, pipelineMode };
}
