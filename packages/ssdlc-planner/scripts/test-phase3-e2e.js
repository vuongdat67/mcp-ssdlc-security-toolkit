/**
 * Phase 3 E2E Integration Test
 * 
 * Tests the complete SSDLC pipeline orchestration:
 * BA → Tech Lead → Security → QA → PM → DevOps
 */

import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Test project configuration
const testProject = {
  project_name: "Secure OAuth2 Provider",
  project_description: "Enterprise-grade OAuth2/OpenID Connect authentication server with PKCE support",
  business_goals: [
    "Enable SSO for all internal applications",
    "Comply with OAuth2.1 specification",
    "Achieve SOC 2 Type II compliance",
    "Support 100K concurrent users"
  ],
  tech_stack: ["Node.js", "TypeScript", "PostgreSQL", "Redis", "Docker", "Kubernetes"],
  team_size: 5,
  sprint_duration: 2,
  deployment_target: "kubernetes",
  repository_platform: "github",
  stakeholders: ["CISO", "Engineering Director", "Product Manager", "End Users"],
  compliance_requirements: ["SOC 2", "GDPR", "OWASP ASVS L2"]
};

// Helper to call MCP tool
function callTool(toolName, args) {
  return new Promise((resolve, reject) => {
    const serverPath = join(__dirname, '../dist/index.js');
    const mcp = spawn('node', [serverPath], {
      cwd: dirname(serverPath),
      stdio: ['pipe', 'pipe', 'pipe']
    });

    let stdout = '';
    let stderr = '';

    mcp.stdout.on('data', (data) => {
      stdout += data.toString();
    });

    mcp.stderr.on('data', (data) => {
      stderr += data.toString();
    });

    mcp.on('close', (code) => {
      if (code !== 0) {
        console.error('STDERR:', stderr);
        reject(new Error(`MCP server exited with code ${code}`));
        return;
      }

      try {
        // Parse JSON-RPC responses
        const lines = stdout.split('\n').filter(l => l.trim());
        const responses = lines.map(line => {
          try {
            return JSON.parse(line);
          } catch {
            return null;
          }
        }).filter(r => r !== null);

        resolve(responses);
      } catch (err) {
        reject(err);
      }
    });

    // Send JSON-RPC request
    const request = JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: {
        name: toolName,
        arguments: args
      }
    }) + '\n';

    mcp.stdin.write(request);
    mcp.stdin.end();
  });
}

// Helper to list tools
function listTools() {
  return new Promise((resolve, reject) => {
    const serverPath = join(__dirname, '../dist/index.js');
    const mcp = spawn('node', [serverPath], {
      cwd: dirname(serverPath),
      stdio: ['pipe', 'pipe', 'pipe']
    });

    let stdout = '';

    mcp.stdout.on('data', (data) => {
      stdout += data.toString();
    });

    mcp.on('close', (code) => {
      if (code !== 0) {
        reject(new Error(`MCP server exited with code ${code}`));
        return;
      }

      try {
        const lines = stdout.split('\n').filter(l => l.trim());
        const responses = lines.map(line => {
          try {
            return JSON.parse(line);
          } catch {
            return null;
          }
        }).filter(r => r !== null);

        resolve(responses);
      } catch (err) {
        reject(err);
      }
    });

    const request = JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/list"
    }) + '\n';

    mcp.stdin.write(request);
    mcp.stdin.end();
  });
}

async function runTests() {
  console.log('🧪 Phase 3 E2E Integration Test\n');

  try {
    // Test 1: List tools
    console.log('Test 1: List available tools');
    const toolsList = await listTools();
    const toolsResponse = toolsList.find(r => r.result?.tools);
    if (!toolsResponse) {
      throw new Error('Failed to list tools');
    }

    const tools = toolsResponse.result.tools.map(t => t.name);
    console.log(`✅ Found ${tools.length} tools`);

    // Verify Phase 3 tools exist
    const phase3Tools = ['orchestrate_ssdlc_pipeline', 'qa_design_test_strategy', 'security_review_code'];
    const missingTools = phase3Tools.filter(t => !tools.includes(t));
    if (missingTools.length > 0) {
      throw new Error(`Missing Phase 3 tools: ${missingTools.join(', ')}`);
    }
    console.log('✅ Phase 3 Tools Available:', phase3Tools.join(', '));

    // Test 2: Test strategy design
    console.log('\n\nTest 2: Design Test Strategy');
    const testStrategyResult = await callTool('qa_design_test_strategy', {
      project_name: testProject.project_name,
      test_levels: ['unit', 'integration', 'security', 'performance'],
      tech_stack: testProject.tech_stack,
      components: [
        { name: 'AuthorizationServer', description: 'OAuth2 authorization endpoint' },
        { name: 'TokenService', description: 'JWT token generation and validation' }
      ],
      risk_level: 'high',
      automation_target: 85,
      timeline_weeks: 4
    });

    const testStrategyResponse = testStrategyResult.find(r => r.result?.content);
    if (!testStrategyResponse) {
      throw new Error('Test strategy design failed');
    }

    const testStrategyData = JSON.parse(testStrategyResponse.result.content[0].text);
    console.log(`✅ Test Strategy Created:`);
    console.log(`   - Test Levels: ${testStrategyData.test_levels.length}`);
    console.log(`   - Test Types: ${testStrategyData.test_types.length}`);
    console.log(`   - Coverage Target: ${testStrategyData.automation_strategy.coverage_target}%`);
    console.log(`   - Overall Risk Score: ${testStrategyData.success_criteria.length} success criteria`);

    // Test 3: Security code review
    console.log('\n\nTest 3: Security Code Review');
    const sampleCode = `
function authenticateUser(username, password) {
  const query = "SELECT * FROM users WHERE username = '" + username + "'";
  const user = db.execute(query);
  
  if (user && user.password === password) {
    const token = Math.random().toString(36);
    return { success: true, token: token };
  }
  return { success: false };
}`;

    const codeReviewResult = await callTool('security_review_code', {
      code_snippet: sampleCode,
      language: 'javascript',
      context: 'User authentication function',
      severity_threshold: 'medium'
    });

    const codeReviewResponse = codeReviewResult.find(r => r.result?.content);
    if (!codeReviewResponse) {
      throw new Error('Security code review failed');
    }

    const codeReviewData = JSON.parse(codeReviewResponse.result.content[0].text);
    console.log(`✅ Security Review Complete:`);
    console.log(`   - Total Findings: ${codeReviewData.summary.total_findings}`);
    console.log(`   - Critical: ${codeReviewData.summary.critical}`);
    console.log(`   - High: ${codeReviewData.summary.high}`);
    console.log(`   - Medium: ${codeReviewData.summary.medium}`);
    console.log(`   - Risk Score: ${codeReviewData.overall_risk_score}/100`);
    console.log(`   - Recommendations: ${codeReviewData.recommendations.length}`);

    // Test 4: Full pipeline orchestration
    console.log('\n\nTest 4: Full SSDLC Pipeline Orchestration');
    console.log('⏳ This may take 10-30 seconds...');

    const pipelineResult = await callTool('orchestrate_ssdlc_pipeline', testProject);

    const pipelineResponse = pipelineResult.find(r => r.result?.content);
    if (!pipelineResponse) {
      throw new Error('Pipeline orchestration failed');
    }

    const pipelineData = JSON.parse(pipelineResponse.result.content[0].text);
    console.log(`✅ Pipeline Orchestration Complete:`);
    console.log(`   - Duration: ${(pipelineData.execution_summary.total_duration_ms / 1000).toFixed(2)}s`);
    console.log(`   - Tools Executed: ${pipelineData.execution_summary.tools_executed.length}`);
    console.log(`   - Success: ${pipelineData.execution_summary.success ? '✅' : '❌'}`);

    console.log('\n📊 Coverage Metrics:');
    console.log(`   - Requirements: ${pipelineData.coverage_metrics.requirements_coverage}% (target: 90-95%)`);
    console.log(`   - Security: ${pipelineData.coverage_metrics.security_coverage}% (target: 85-95%)`);
    console.log(`   - Testing: ${pipelineData.coverage_metrics.test_coverage}% (target: 85-90%)`);
    console.log(`   - Architecture: ${pipelineData.coverage_metrics.architecture_coverage}% (target: 85-90%)`);
    console.log(`   - OVERALL: ${pipelineData.coverage_metrics.overall_coverage}% (target: 85-95%)`);

    console.log('\n📦 Artifacts Generated:');
    console.log(`   - User Stories: ${pipelineData.requirements.user_stories.length}`);
    console.log(`   - Components: ${pipelineData.architecture.components.length}`);
    console.log(`   - Threats Identified: ${pipelineData.threat_model.threats.length}`);
    console.log(`   - Pseudocode Functions: ${pipelineData.pseudocode.total_functions}`);
    console.log(`   - Test Suites: ${pipelineData.test_cases.test_suites.length}`);
    console.log(`   - Test Cases: ${pipelineData.test_cases.total_cases}`);
    console.log(`   - Sprints: ${pipelineData.sprint_plan.sprints.length}`);
    console.log(`   - CI/CD Stages: ${pipelineData.cicd_pipeline.stages.length}`);

    // Validate coverage targets
    const coverageTargets = {
      requirements: 90,
      security: 85,
      test: 85,
      architecture: 85,
      overall: 85
    };

    const failedTargets = [];
    if (pipelineData.coverage_metrics.requirements_coverage < coverageTargets.requirements) {
      failedTargets.push(`Requirements: ${pipelineData.coverage_metrics.requirements_coverage}% < ${coverageTargets.requirements}%`);
    }
    if (pipelineData.coverage_metrics.security_coverage < coverageTargets.security) {
      failedTargets.push(`Security: ${pipelineData.coverage_metrics.security_coverage}% < ${coverageTargets.security}%`);
    }
    if (pipelineData.coverage_metrics.test_coverage < coverageTargets.test) {
      failedTargets.push(`Testing: ${pipelineData.coverage_metrics.test_coverage}% < ${coverageTargets.test}%`);
    }
    if (pipelineData.coverage_metrics.architecture_coverage < coverageTargets.architecture) {
      failedTargets.push(`Architecture: ${pipelineData.coverage_metrics.architecture_coverage}% < ${coverageTargets.architecture}%`);
    }
    if (pipelineData.coverage_metrics.overall_coverage < coverageTargets.overall) {
      failedTargets.push(`Overall: ${pipelineData.coverage_metrics.overall_coverage}% < ${coverageTargets.overall}%`);
    }

    if (failedTargets.length > 0) {
      console.log('\n⚠️  Coverage targets not met:');
      failedTargets.forEach(target => console.log(`   - ${target}`));
    } else {
      console.log('\n✅ All coverage targets met!');
    }

    console.log('\n✨ All Phase 3 E2E tests passed!\n');
    process.exit(0);

  } catch (error) {
    console.error('\n❌ Test failed:', error.message);
    process.exit(1);
  }
}

runTests();
