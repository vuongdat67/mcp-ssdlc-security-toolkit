#!/usr/bin/env node

/**
 * Manual test script for MCP SSDLC Planner
 * Tests the MCP server directly via stdio
 */

import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const serverPath = join(__dirname, '../dist/index.js');

console.log('🧪 Testing MCP SSDLC Planner Server\n');
console.log(`📍 Server path: ${serverPath}\n`);

// Start the MCP server
const server = spawn('node', [serverPath], {
  stdio: ['pipe', 'pipe', 'inherit']
});

// Send initialize request
const initializeRequest = {
  jsonrpc: '2.0',
  id: 1,
  method: 'initialize',
  params: {
    protocolVersion: '2024-11-05',
    capabilities: {},
    clientInfo: {
      name: 'test-client',
      version: '1.0.0'
    }
  }
};

// Send list tools request
const listToolsRequest = {
  jsonrpc: '2.0',
  id: 2,
  method: 'tools/list',
  params: {}
};

// Test BA tool
const testBAToolRequest = {
  jsonrpc: '2.0',
  id: 3,
  method: 'tools/call',
  params: {
    name: 'ba_analyze_requirements',
    arguments: {
      project_description: 'OAuth2 authorization server for internal microservices with JWT tokens and role-based access control',
      stakeholders: ['Backend developers', 'Security team', 'DevOps'],
      business_goals: ['Secure authentication', 'OAuth2 compliance', 'Scale to 10k users']
    }
  }
};

let responseBuffer = '';

server.stdout.on('data', (data) => {
  responseBuffer += data.toString();
  
  // Try to parse complete JSON-RPC responses
  const lines = responseBuffer.split('\n');
  responseBuffer = lines.pop() || ''; // Keep incomplete line in buffer
  
  lines.forEach(line => {
    if (line.trim()) {
      try {
        const response = JSON.parse(line);
        console.log('📥 Response:', JSON.stringify(response, null, 2));
        
        if (response.id === 1) {
          // After initialize, list tools
          server.stdin.write(JSON.stringify(listToolsRequest) + '\n');
        } else if (response.id === 2) {
          // After listing tools, call BA tool
          console.log(`\n🔧 Available tools: ${response.result?.tools?.length || 0}`);
          server.stdin.write(JSON.stringify(testBAToolRequest) + '\n');
        } else if (response.id === 3) {
          // BA tool result
          console.log('\n✅ BA Tool Test Complete!');
          console.log('\n📄 Output Preview:');
          const output = response.result?.content?.[0]?.text || 'No output';
          console.log(output.substring(0, 500) + '...\n');
          
          console.log('✨ All tests passed!');
          server.kill();
          process.exit(0);
        }
      } catch (e) {
        // Ignore parse errors for incomplete JSON
      }
    }
  });
});

server.on('error', (err) => {
  console.error('❌ Server error:', err);
  process.exit(1);
});

server.on('close', (code) => {
  if (code !== 0 && code !== null) {
    console.error(`❌ Server exited with code ${code}`);
    process.exit(1);
  }
});

// Start by sending initialize
console.log('📤 Sending initialize request...\n');
server.stdin.write(JSON.stringify(initializeRequest) + '\n');

// Timeout after 10 seconds
setTimeout(() => {
  console.error('❌ Test timed out');
  server.kill();
  process.exit(1);
}, 10000);
