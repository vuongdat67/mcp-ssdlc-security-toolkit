import { describe, it, expect, beforeAll } from 'vitest';
import { parseJSON, normalizeJSON } from '@mcp-ssdlc/core';

describe('MCP Server Integration Tests', () => {
  describe('JSON Normalization Layer', () => {
    it('should handle backtick JSON from Claude', () => {
      const backticInput = `{
        \`project_name\`: \`Healthcare System\`,
        \`project_description\`: \`A secure system\`,
        \`business_goals\`: [\`Security\`, \`HIPAA\`],
        \`stakeholders\`: [\`Patients\`, \`Doctors\`]
      }`;

      const normalized = normalizeJSON(backticInput, 'test');
      const parsed = JSON.parse(normalized);
      
      expect(parsed.project_name).toBe('Healthcare System');
      expect(parsed.business_goals).toEqual(['Security', 'HIPAA']);
    });

    it('should handle single quotes', () => {
      const singleQuoteInput = `{
        'project_name': 'Test',
        'business_goals': ['Goal1']
      }`;

      const parsed = parseJSON(singleQuoteInput, 'test');
      expect(parsed.project_name).toBe('Test');
    });

    it('should remove trailing commas', () => {
      const trailingCommaInput = `{
        "project_name": "Test",
        "business_goals": ["Goal1",],
      }`;

      const normalized = normalizeJSON(trailingCommaInput, 'test');
      const parsed = JSON.parse(normalized);
      expect(parsed).toHaveProperty('project_name');
    });

    it('should remove comments', () => {
      const commentInput = `{
        "project_name": "Test", // This is a comment
        "business_goals": ["Goal1"] // Another comment
      }`;

      const normalized = normalizeJSON(commentInput, 'test');
      const parsed = JSON.parse(normalized);
      expect(parsed.project_name).toBe('Test');
    });

    it('should handle mixed malformations', () => {
      const messyInput = `{
        \`project_name\`: \`Test\`, // Comment
        'business_goals': ['Goal1',], // Trailing comma
        "stakeholders": ["User1"]
      }`;

      const parsed = parseJSON(messyInput, 'test');
      expect(parsed.project_name).toBe('Test');
      expect(parsed.business_goals).toEqual(['Goal1']);
      expect(parsed.stakeholders).toEqual(['User1']);
    });
  });

  describe('Tool Execution Integration', () => {
    it('should execute BA tool with normalized JSON input', async () => {
      const { baAnalyzeRequirements } = await import('../../src/tools/requirements/analyze-requirements.js');
      
      // Simulate malformed input from Claude
      const rawInput = `{
        \`project_name\`: \`Healthcare API\`,
        \`project_description\`: \`Secure healthcare system with authentication\`,
        \`business_goals\`: [\`HIPAA compliance\`],
        \`stakeholders\`: [\`Patients\`, \`Doctors\`]
      }`;

      // Normalize before passing to tool
      const normalizedInput = parseJSON(rawInput, 'ba_analyze_requirements');
      
      const result = await baAnalyzeRequirements(normalizedInput);
      const output = JSON.parse(result.content[0].text);
      
      expect(output.user_stories.length).toBeGreaterThan(0);
      expect(output.project_name).toBe('Healthcare API');
    });

    it('should execute architecture tool and return JSON', async () => {
      const { techleadDesignArchitecture } = await import('../../src/tools/architecture/design-architecture.js');
      
      const input = {
        project_name: "OAuth2 Server",
        user_stories: [
          {
            id: "US-1",
            as_a: "API Consumer",
            i_want: "obtain access token",
            so_that: "I can call protected APIs",
            acceptance_criteria: ["Token issued with expiry", "Refresh token supported"]
          }
        ],
        business_goals: ["Secure authentication"],
        constraints: ["Node.js", "Redis"]
      };

      const result = await techleadDesignArchitecture(input);
      
      // CRITICAL: Must be JSON, not markdown
      let output;
      expect(() => {
        output = JSON.parse(result.content[0].text);
      }).not.toThrow();
      
      expect(output).toHaveProperty('components');
      expect(output).toHaveProperty('mermaid_diagram');
      expect(typeof output).toBe('object');
    });
  });

  describe('Tool Output Validation', () => {
    it('should validate BA tool output schema', async () => {
      const { baAnalyzeRequirements } = await import('../../src/tools/requirements/analyze-requirements.js');
      
      const input = {
        project_name: "Test Project",
        project_description: "Test with authentication and logging",
        business_goals: ["Security"],
        stakeholders: ["Users"]
      };

      const result = await baAnalyzeRequirements(input);
      const output = JSON.parse(result.content[0].text);
      
      // Validate schema
      expect(output).toMatchObject({
        project_name: expect.any(String),
        timestamp: expect.any(String),
        user_stories: expect.arrayContaining([
          expect.objectContaining({
            id: expect.any(String),
            as_a: expect.any(String),
            i_want: expect.any(String),
            so_that: expect.any(String),
            acceptance_criteria: expect.any(Array)
          })
        ]),
        prioritization_matrix: expect.objectContaining({
          high_priority: expect.any(Array),
          medium_priority: expect.any(Array),
          low_priority: expect.any(Array)
        }),
        security_requirements: expect.any(Array)
      });
    });

    it('should validate architecture tool output schema', async () => {
      const { techleadDesignArchitecture } = await import('../../src/tools/architecture/design-architecture.js');
      
      const input = {
        project_name: "Test",
        user_stories: [],
        business_goals: [],
        constraints: []
      };

      const result = await techleadDesignArchitecture(input);
      const output = JSON.parse(result.content[0].text);
      
      // Validate schema
      expect(output).toMatchObject({
        mermaid_diagram: expect.any(String),
        components: expect.arrayContaining([
          expect.objectContaining({
            name: expect.any(String),
            responsibilities: expect.any(Array),
            security: expect.any(Array)
          })
        ]),
        trust_boundaries: expect.any(Array),
        data_flows: expect.any(Array),
        technology_stack: expect.any(Object),
        security_architecture: expect.objectContaining({
          encryption: expect.any(Object),
          authentication: expect.any(String),
          authorization: expect.any(String)
        }),
        scalability: expect.any(Object),
        constraints_applied: expect.any(Array)
      });
    });
  });

  describe('Error Recovery', () => {
    it('should provide helpful error for completely invalid JSON', () => {
      const invalidJSON = 'not json at all {{{ ]]]';
      
      expect(() => {
        parseJSON(invalidJSON, 'test_tool');
      }).toThrow();
    });

    it('should handle tool validation errors gracefully', async () => {
      const { baAnalyzeRequirements } = await import('../../src/tools/requirements/analyze-requirements.js');
      
      const invalidInput = {
        wrong_field: "test"
      };

      await expect(baAnalyzeRequirements(invalidInput)).rejects.toThrow();
    });
  });

  describe('Performance Tests', () => {
    it('should complete BA analysis in under 2 seconds', async () => {
      const { baAnalyzeRequirements } = await import('../../src/tools/requirements/analyze-requirements.js');
      
      const input = {
        project_name: "Performance Test",
        project_description: "Simple project for timing",
        business_goals: ["Speed"],
        stakeholders: ["Users"]
      };

      const start = Date.now();
      await baAnalyzeRequirements(input);
      const duration = Date.now() - start;
      
      expect(duration).toBeLessThan(2000);
    });

    it('should complete architecture design in under 2 seconds', async () => {
      const { techleadDesignArchitecture } = await import('../../src/tools/architecture/design-architecture.js');
      
      const input = {
        project_name: "Performance Test",
        user_stories: [],
        business_goals: [],
        constraints: []
      };

      const start = Date.now();
      await techleadDesignArchitecture(input);
      const duration = Date.now() - start;
      
      expect(duration).toBeLessThan(2000);
    });
  });
});
