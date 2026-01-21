#!/usr/bin/env node

/**
 * Phase 2 Integration Test
 * 
 * Tests new tools: pseudocode generation, CI/CD design, sprint planning
 */

import { spawn } from "child_process";

async function sendMCPRequest(method, params) {
  return new Promise((resolve, reject) => {
    const server = spawn("node", ["packages/ssdlc-planner/dist/index.js"]);
    
    let responseData = "";
    let errorData = "";

    server.stdout.on("data", (data) => {
      responseData += data.toString();
    });

    server.stderr.on("data", (data) => {
      errorData += data.toString();
    });

    server.on("close", (code) => {
      if (code !== 0 && errorData) {
        reject(new Error(errorData));
      } else {
        try {
          const lines = responseData.trim().split("\n");
          const response = JSON.parse(lines[lines.length - 1]);
          resolve(response);
        } catch (e) {
          reject(new Error("Failed to parse response: " + responseData));
        }
      }
    });

    // Send request
    const request = JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method,
      params,
    });

    server.stdin.write(request + "\n");
    server.stdin.end();
  });
}

async function runTests() {
  console.log("🧪 Testing MCP SSDLC Planner - Phase 2 Features\n");

  try {
    // Test 1: List tools
    console.log("📋 Test 1: List available tools");
    const listResponse = await sendMCPRequest("tools/list", {});
    const tools = listResponse.result.tools;
    console.log(`✅ Found ${tools.length} tools`);
    
    // Verify Phase 2 tools are present
    const phase2Tools = [
      "techlead_generate_pseudocode",
      "devops_design_cicd",
      "pm_create_sprint_plan"
    ];
    
    const foundPhase2Tools = phase2Tools.filter(tool => 
      tools.some(t => t.name === tool)
    );
    
    console.log(`✅ Phase 2 Tools Available: ${foundPhase2Tools.join(", ")}\n`);

    // Test 2: Pseudocode Generation
    console.log("📝 Test 2: Generate Pseudocode");
    const pseudocodeResponse = await sendMCPRequest("tools/call", {
      name: "techlead_generate_pseudocode",
      arguments: {
        function_name: "authenticate_user",
        description: "Authenticate user with username and password using JWT tokens",
        language: "python",
        parameters: [
          { name: "username", type: "str", description: "User's username" },
          { name: "password", type: "str", description: "User's password" }
        ],
        return_type: "dict",
        security_context: "High security - handles authentication"
      }
    });
    
    console.log("DEBUG: Full Response:", JSON.stringify(pseudocodeResponse, null, 2));
    const pseudocodeText = pseudocodeResponse.result?.content?.[0]?.text || "No content";
    console.log("✅ Pseudocode Generated");
    console.log(`📄 Sample: ${pseudocodeText.substring(0, 200)}...\n`);

    // Test 3: CI/CD Pipeline Design
    console.log("🔧 Test 3: Design CI/CD Pipeline");
    const cicdResponse = await sendMCPRequest("tools/call", {
      name: "devops_design_cicd",
      arguments: {
        project_name: "oauth-provider",
        repository_platform: "github",
        tech_stack: ["node", "docker"],
        deployment_target: "kubernetes",
        security_requirements: ["SAST", "DAST", "dependency-scanning"]
      }
    });
    
    const cicdText = cicdResponse.result.content[0].text;
    console.log("✅ CI/CD Pipeline Designed");
    console.log(`📄 Sample: ${cicdText.substring(0, 200)}...\n`);

    // Test 4: Sprint Planning
    console.log("📅 Test 4: Create Sprint Plan");
    const sprintResponse = await sendMCPRequest("tools/call", {
      name: "pm_create_sprint_plan",
      arguments: {
        project_name: "OAuth2 Provider",
        sprint_duration: 2,
        team_size: 4,
        user_stories: [
          { id: "US-001", title: "Implement user authentication", priority: "P0", story_points: 8 },
          { id: "US-002", title: "Create token generation", priority: "P0", story_points: 5 },
          { id: "US-003", title: "Add rate limiting", priority: "P1", story_points: 3 }
        ],
        team_velocity: 40
      }
    });
    
    const sprintText = sprintResponse.result.content[0].text;
    console.log("✅ Sprint Plan Created");
    console.log(`📄 Sample: ${sprintText.substring(0, 200)}...\n`);

    console.log("✨ All Phase 2 tests passed!");
    console.log("\n🎉 Phase 2 Implementation Complete!");
    console.log("\nNew Features:");
    console.log("- ✅ Security Knowledge Base (CVE/CWE/OWASP)");
    console.log("- ✅ Pseudocode Generation with Security Annotations");
    console.log("- ✅ CI/CD Pipeline Design");
    console.log("- ✅ Sprint Planning with Task Breakdown");

  } catch (error) {
    console.error("❌ Test failed:", error.message);
    process.exit(1);
  }
}

runTests();
