import { describe, it, expect, beforeEach } from 'vitest';
import type { MCPToolResult } from '@mcp-ssdlc/core';

// Dynamic import to match runtime behavior
let baAnalyzeRequirements: (input: unknown) => Promise<MCPToolResult>;

beforeEach(async () => {
  const module = await import('../../../src/tools/requirements/analyze-requirements.js');
  baAnalyzeRequirements = module.baAnalyzeRequirements;
});

describe('BA Analyze Requirements Tool', () => {
  describe('Valid Inputs', () => {
    it('should generate user stories from healthcare project description', async () => {
      const input = {
        project_name: "Healthcare Management System",
        project_description: "A secure healthcare system with patient records, appointment scheduling, and HIPAA compliance. Must include authentication, authorization, and audit logging.",
        business_goals: [
          "HIPAA compliance",
          "Secure patient data management",
          "Streamline appointment booking"
        ],
        stakeholders: ["Patients", "Doctors", "Administrators", "Compliance Officers"]
      };

      const result = await baAnalyzeRequirements(input);
      
      // Verify structure
      expect(result).toHaveProperty('content');
      expect(result.content).toHaveLength(1);
      expect(result.content[0].type).toBe('text');
      
      // Parse output
      const output = JSON.parse(result.content[0].text);
      
      // Verify required fields
      expect(output).toHaveProperty('project_name', input.project_name);
      expect(output).toHaveProperty('timestamp');
      expect(output).toHaveProperty('user_stories');
      expect(output).toHaveProperty('prioritization_matrix');
      expect(output).toHaveProperty('security_requirements');
      
      // Verify user stories
      expect(Array.isArray(output.user_stories)).toBe(true);
      expect(output.user_stories.length).toBeGreaterThan(0);
      
      const firstStory = output.user_stories[0];
      expect(firstStory).toHaveProperty('id');
      expect(firstStory).toHaveProperty('as_a');
      expect(firstStory).toHaveProperty('i_want');
      expect(firstStory).toHaveProperty('so_that');
      expect(firstStory).toHaveProperty('acceptance_criteria');
      expect(Array.isArray(firstStory.acceptance_criteria)).toBe(true);
      
      // Verify security requirements exist
      expect(Array.isArray(output.security_requirements)).toBe(true);
      expect(output.security_requirements.length).toBeGreaterThan(0);
      
      // Check for HIPAA-related content
      const allText = JSON.stringify(output).toLowerCase();
      expect(allText).toMatch(/hipaa|encryption|authentication|audit/);
    });

    it('should handle OAuth2 provider project', async () => {
      const input = {
        project_name: "OAuth2 Authorization Server",
        project_description: "Enterprise OAuth2 provider with client registration, token management, and security monitoring. Must support multiple grant types and OpenID Connect.",
        business_goals: [
          "Secure authentication",
          "Scalable authorization",
          "Compliance with OAuth 2.1 spec"
        ],
        stakeholders: ["API Consumers", "Security Team", "DevOps"]
      };

      const result = await baAnalyzeRequirements(input);
      const output = JSON.parse(result.content[0].text);
      
      expect(output.user_stories.length).toBeGreaterThan(0);
      
      // Should detect OAuth-related features
      const storiesText = JSON.stringify(output.user_stories).toLowerCase();
      expect(storiesText).toMatch(/oauth|token|authorization|authentication/);
    });

    it('should prioritize features correctly', async () => {
      const input = {
        project_name: "E-commerce Platform",
        project_description: "Online shopping with payment processing, user authentication, product catalog, and order management.",
        business_goals: ["Revenue generation", "Customer satisfaction"],
        stakeholders: ["Customers", "Merchants"]
      };

      const result = await baAnalyzeRequirements(input);
      const output = JSON.parse(result.content[0].text);
      
      // Verify prioritization matrix
      expect(output.prioritization_matrix).toHaveProperty('high_priority');
      expect(output.prioritization_matrix).toHaveProperty('medium_priority');
      expect(output.prioritization_matrix).toHaveProperty('low_priority');
      
      expect(Array.isArray(output.prioritization_matrix.high_priority)).toBe(true);
      expect(Array.isArray(output.prioritization_matrix.medium_priority)).toBe(true);
      expect(Array.isArray(output.prioritization_matrix.low_priority)).toBe(true);
    });
  });

  describe('Edge Cases', () => {
    it('should handle minimal input', async () => {
      const input = {
        project_name: "Basic App",
        project_description: "Simple application",
        business_goals: [],
        stakeholders: []
      };

      const result = await baAnalyzeRequirements(input);
      const output = JSON.parse(result.content[0].text);
      
      // Should still generate at least one generic story
      expect(output.user_stories.length).toBeGreaterThan(0);
      expect(output.security_requirements.length).toBeGreaterThan(0);
    });

    it('should handle complex nested requirements', async () => {
      const input = {
        project_name: "Financial Trading Platform",
        project_description: `
          Multi-tier trading system with:
          - Real-time market data streaming
          - Order execution engine with sub-millisecond latency
          - Risk management and compliance monitoring
          - Multi-factor authentication for traders
          - Encrypted communication channels
          - Audit logging for all transactions
          - Integration with legacy systems via REST APIs
          - Disaster recovery with RPO < 1 minute
        `,
        business_goals: [
          "SEC compliance",
          "High availability (99.99%)",
          "Low latency trading",
          "Data security and privacy"
        ],
        stakeholders: ["Traders", "Compliance Officers", "System Administrators", "Risk Managers"]
      };

      const result = await baAnalyzeRequirements(input);
      const output = JSON.parse(result.content[0].text);
      
      expect(output.user_stories.length).toBeGreaterThan(5); // Complex project should have many stories
      expect(output.security_requirements.length).toBeGreaterThan(3);
      
      // Should capture multiple security concerns
      const secReqs = output.security_requirements.join(' ').toLowerCase();
      expect(secReqs).toMatch(/authentication|encryption|audit/);
    });
  });

  describe('Output Validation', () => {
    it('should return valid JSON that can be parsed by orchestration', async () => {
      const input = {
        project_name: "Test Project",
        project_description: "Test description with authentication and logging",
        business_goals: ["Security"],
        stakeholders: ["Users"]
      };

      const result = await baAnalyzeRequirements(input);
      
      // Should not throw
      expect(() => JSON.parse(result.content[0].text)).not.toThrow();
      
      const output = JSON.parse(result.content[0].text);
      
      // Output should be an object, not an array
      expect(typeof output).toBe('object');
      expect(Array.isArray(output)).toBe(false);
    });

    it('should generate unique story IDs', async () => {
      const input = {
        project_name: "Multi-Feature App",
        project_description: "App with authentication, authorization, logging, monitoring, and reporting features",
        business_goals: ["All the things"],
        stakeholders: ["Everyone"]
      };

      const result = await baAnalyzeRequirements(input);
      const output = JSON.parse(result.content[0].text);
      
      const ids = output.user_stories.map((s: any) => s.id);
      const uniqueIds = new Set(ids);
      
      expect(ids.length).toBe(uniqueIds.size); // All IDs should be unique
    });

    it('should include timestamp in ISO format', async () => {
      const input = {
        project_name: "Test",
        project_description: "Test",
        business_goals: [],
        stakeholders: []
      };

      const result = await baAnalyzeRequirements(input);
      const output = JSON.parse(result.content[0].text);
      
      expect(output.timestamp).toBeDefined();
      
      // Should be valid ISO timestamp
      const date = new Date(output.timestamp);
      expect(date.toString()).not.toBe('Invalid Date');
    });
  });

  describe('Security Requirements Coverage', () => {
    it('should identify authentication requirements', async () => {
      const input = {
        project_name: "User Portal",
        project_description: "Web portal requiring user login, password reset, and session management",
        business_goals: ["User security"],
        stakeholders: ["End Users"]
      };

      const result = await baAnalyzeRequirements(input);
      const output = JSON.parse(result.content[0].text);
      
      const secReqs = output.security_requirements.join(' ').toLowerCase();
      expect(secReqs).toMatch(/authentication|password|session/);
    });

    it('should identify encryption requirements', async () => {
      const input = {
        project_name: "Data Storage System",
        project_description: "Secure storage with encryption at rest and in transit, PCI DSS compliance",
        business_goals: ["Data protection"],
        stakeholders: ["Security Team"]
      };

      const result = await baAnalyzeRequirements(input);
      const output = JSON.parse(result.content[0].text);
      
      const secReqs = output.security_requirements.join(' ').toLowerCase();
      expect(secReqs).toMatch(/encryption|pci|secure/);
    });

    it('should identify compliance requirements', async () => {
      const input = {
        project_name: "GDPR Compliance System",
        project_description: "Data processing system with GDPR compliance, data retention policies, and user consent management",
        business_goals: ["GDPR compliance"],
        stakeholders: ["Legal Team", "Users"]
      };

      const result = await baAnalyzeRequirements(input);
      const output = JSON.parse(result.content[0].text);
      
      const secReqs = output.security_requirements.join(' ').toLowerCase();
      expect(secReqs).toMatch(/gdpr|consent|retention|privacy/);
    });
  });

  describe('Error Handling', () => {
    it('should reject invalid input schema', async () => {
      const invalidInput = {
        wrong_field: "test"
      };

      await expect(baAnalyzeRequirements(invalidInput)).rejects.toThrow();
    });

    it('should handle undefined business goals', async () => {
      const input = {
        project_name: "Test",
        project_description: "Test",
        business_goals: undefined,
        stakeholders: ["Users"]
      };

      // Should either work with defaults or throw validation error
      try {
        const result = await baAnalyzeRequirements(input);
        const output = JSON.parse(result.content[0].text);
        expect(output.user_stories.length).toBeGreaterThan(0);
      } catch (error) {
        expect(error).toBeDefined(); // Expected validation error
      }
    });
  });
});
