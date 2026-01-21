import { describe, it, expect, beforeEach } from 'vitest';
import type { MCPToolResult } from '@mcp-ssdlc/core';

let techleadDesignArchitecture: (input: unknown) => Promise<MCPToolResult>;

beforeEach(async () => {
  const module = await import('../../../src/tools/architecture/design-architecture.js');
  techleadDesignArchitecture = module.techleadDesignArchitecture;
});

describe('TechLead Design Architecture Tool', () => {
  describe('Valid Inputs', () => {
    it('should generate architecture with JSON output', async () => {
      const input = {
        project_name: "Healthcare API",
        user_stories: [
          {
            id: "US-1",
            as_a: "Patient",
            i_want: "view my medical records",
            so_that: "I can track my health history",
            acceptance_criteria: ["Records displayed securely", "Audit log created"]
          }
        ],
        business_goals: ["HIPAA compliance"],
        constraints: ["Node.js", "PostgreSQL", "Must be HIPAA compliant"]
      };

      const result = await techleadDesignArchitecture(input);
      
      // Verify structure
      expect(result).toHaveProperty('content');
      expect(result.content).toHaveLength(1);
      expect(result.content[0].type).toBe('text');
      
      // CRITICAL: Output must be valid JSON
      let output;
      expect(() => {
        output = JSON.parse(result.content[0].text);
      }).not.toThrow('Output must be valid JSON for orchestration');
      
      // Verify JSON structure (not markdown)
      expect(typeof output).toBe('object');
      expect(Array.isArray(output)).toBe(false);
      
      // Verify required fields
      expect(output).toHaveProperty('mermaid_diagram');
      expect(output).toHaveProperty('components');
      expect(output).toHaveProperty('trust_boundaries');
      expect(output).toHaveProperty('data_flows');
      expect(output).toHaveProperty('technology_stack');
      expect(output).toHaveProperty('security_architecture');
      
      // Verify components structure
      expect(Array.isArray(output.components)).toBe(true);
      expect(output.components.length).toBeGreaterThan(0);
      
      const firstComponent = output.components[0];
      expect(firstComponent).toHaveProperty('name');
      expect(firstComponent).toHaveProperty('responsibilities');
      expect(firstComponent).toHaveProperty('security');
    });

    it('should generate valid Mermaid diagram', async () => {
      const input = {
        project_name: "OAuth2 Server",
        user_stories: [],
        business_goals: ["Secure authentication"],
        constraints: ["Python", "Redis"]
      };

      const result = await techleadDesignArchitecture(input);
      const output = JSON.parse(result.content[0].text);
      
      expect(output.mermaid_diagram).toBeDefined();
      expect(output.mermaid_diagram).toContain('graph');
      expect(output.mermaid_diagram.trim().length).toBeGreaterThan(10);
    });

    it('should respect technology constraints', async () => {
      const input = {
        project_name: "Python API",
        user_stories: [],
        business_goals: [],
        constraints: ["Python", "MongoDB", "React"]
      };

      const result = await techleadDesignArchitecture(input);
      const output = JSON.parse(result.content[0].text);
      
      expect(output.constraints_applied).toEqual(input.constraints);
      
      // Technology stack should reflect constraints
      const techStack = JSON.stringify(output.technology_stack).toLowerCase();
      expect(techStack).toMatch(/python/);
    });
  });

  describe('Security Architecture', () => {
    it('should include trust boundaries', async () => {
      const input = {
        project_name: "Secure API",
        user_stories: [],
        business_goals: ["Security"],
        constraints: []
      };

      const result = await techleadDesignArchitecture(input);
      const output = JSON.parse(result.content[0].text);
      
      expect(Array.isArray(output.trust_boundaries)).toBe(true);
      expect(output.trust_boundaries.length).toBeGreaterThan(0);
      
      // Should mention public/authenticated boundaries
      const boundaries = output.trust_boundaries.join(' ').toLowerCase();
      expect(boundaries).toMatch(/public|authenticated|encrypted/);
    });

    it('should define data flows with security', async () => {
      const input = {
        project_name: "Data Pipeline",
        user_stories: [],
        business_goals: [],
        constraints: []
      };

      const result = await techleadDesignArchitecture(input);
      const output = JSON.parse(result.content[0].text);
      
      expect(Array.isArray(output.data_flows)).toBe(true);
      expect(output.data_flows.length).toBeGreaterThan(0);
      
      const firstFlow = output.data_flows[0];
      expect(firstFlow).toHaveProperty('from');
      expect(firstFlow).toHaveProperty('to');
      expect(firstFlow).toHaveProperty('security');
    });

    it('should specify encryption requirements', async () => {
      const input = {
        project_name: "Encrypted Storage",
        user_stories: [],
        business_goals: ["Data protection"],
        constraints: ["Must encrypt at rest"]
      };

      const result = await techleadDesignArchitecture(input);
      const output = JSON.parse(result.content[0].text);
      
      expect(output.security_architecture).toHaveProperty('encryption');
      expect(output.security_architecture.encryption).toHaveProperty('at_rest');
      expect(output.security_architecture.encryption).toHaveProperty('in_transit');
    });
  });

  describe('Scalability Design', () => {
    it('should include scalability considerations', async () => {
      const input = {
        project_name: "High Traffic API",
        user_stories: [],
        business_goals: ["Handle 10K req/sec"],
        constraints: []
      };

      const result = await techleadDesignArchitecture(input);
      const output = JSON.parse(result.content[0].text);
      
      expect(output).toHaveProperty('scalability');
      expect(output.scalability).toHaveProperty('horizontal_scaling');
      expect(output.scalability).toHaveProperty('caching');
    });
  });

  describe('Output Format Consistency', () => {
    it('should NOT return markdown (critical for orchestration)', async () => {
      const input = {
        project_name: "Test",
        user_stories: [],
        business_goals: [],
        constraints: []
      };

      const result = await techleadDesignArchitecture(input);
      const text = result.content[0].text;
      
      // Should not start with markdown headers
      expect(text).not.toMatch(/^#\s+/);
      expect(text).not.toMatch(/^##\s+/);
      
      // Should be valid JSON
      let parsed;
      expect(() => {
        parsed = JSON.parse(text);
      }).not.toThrow();
      
      expect(typeof parsed).toBe('object');
    });

    it('should be parseable by orchestration pipeline', async () => {
      const input = {
        project_name: "Test",
        user_stories: [],
        business_goals: [],
        constraints: ["Node.js"]
      };

      const result = await techleadDesignArchitecture(input);
      
      // Simulate orchestration parsing
      const output = JSON.parse(result.content[0].text);
      
      // Should be able to extract components
      expect(output.components).toBeDefined();
      expect(Array.isArray(output.components)).toBe(true);
      
      // Should be able to access nested properties
      expect(output.technology_stack).toBeDefined();
      expect(typeof output.technology_stack).toBe('object');
    });
  });

  describe('Error Handling', () => {
    it('should reject invalid input schema', async () => {
      const invalidInput = {
        wrong_field: "test"
      };

      await expect(techleadDesignArchitecture(invalidInput)).rejects.toThrow();
    });

    it('should handle empty user stories', async () => {
      const input = {
        project_name: "Minimal Project",
        user_stories: [],
        business_goals: [],
        constraints: []
      };

      const result = await techleadDesignArchitecture(input);
      const output = JSON.parse(result.content[0].text);
      
      // Should still generate architecture
      expect(output.components.length).toBeGreaterThan(0);
    });
  });

  describe('Real-World Scenarios', () => {
    it('should handle healthcare system architecture', async () => {
      const input = {
        project_name: "Healthcare EHR System",
        user_stories: [
          { id: "US-1", as_a: "Doctor", i_want: "access patient records", so_that: "provide care", acceptance_criteria: [] },
          { id: "US-2", as_a: "Patient", i_want: "view my records", so_that: "understand my health", acceptance_criteria: [] }
        ],
        business_goals: ["HIPAA compliance", "High availability"],
        constraints: ["Node.js", "PostgreSQL", "Must support 1000 concurrent users", "HIPAA compliant"]
      };

      const result = await techleadDesignArchitecture(input);
      const output = JSON.parse(result.content[0].text);
      
      // Should have appropriate components for healthcare
      const componentNames = output.components.map((c: any) => c.name.toLowerCase()).join(' ');
      expect(componentNames).toMatch(/gateway|auth|database|api/);
      
      // Security should be strong
      expect(output.security_architecture.encryption.at_rest).toBeDefined();
      expect(output.security_architecture.authentication).toBeDefined();
    });

    it('should handle microservices architecture', async () => {
      const input = {
        project_name: "E-commerce Platform",
        user_stories: [
          { id: "US-1", as_a: "Customer", i_want: "browse products", so_that: "make purchases", acceptance_criteria: [] },
          { id: "US-2", as_a: "Merchant", i_want: "manage inventory", so_that: "sell items", acceptance_criteria: [] }
        ],
        business_goals: ["Scalability", "High availability"],
        constraints: ["Microservices", "Kubernetes", "React", "Node.js"]
      };

      const result = await techleadDesignArchitecture(input);
      const output = JSON.parse(result.content[0].text);
      
      expect(output.components.length).toBeGreaterThan(2); // Multiple services
      expect(output.scalability).toBeDefined();
    });
  });
});
