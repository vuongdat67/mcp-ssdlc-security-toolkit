import { describe, it, expect } from 'vitest';

describe('SSDLC Orchestration Workflow Tests', () => {
  describe('Orchestration Plan Generation', () => {
    it('should generate valid 7-phase execution plan', async () => {
      const { orchestrateSSDLCPipeline } = await import('../../src/tools/orchestration/orchestrate-pipeline-v2.js');
      
      const input = {
        project_name: "Healthcare Management System",
        project_description: "Secure healthcare platform with HIPAA compliance, patient records, and appointment scheduling",
        business_goals: [
          "HIPAA compliance",
          "Secure patient data",
          "Streamline appointments"
        ],
        tech_stack: ["Node.js", "PostgreSQL", "React"],
        team_size: 8,
        sprint_duration: 2
      };

      const result = await orchestrateSSDLCPipeline(input);
      const plan = JSON.parse(result.content[0].text);
      
      // Validate plan structure
      expect(plan).toHaveProperty('orchestration_id');
      expect(plan.orchestration_id).toMatch(/^ssdlc-\d+$/);
      
      expect(plan).toHaveProperty('phases');
      expect(Array.isArray(plan.phases)).toBe(true);
      expect(plan.phases).toHaveLength(7);
      
      expect(plan).toHaveProperty('execution_instructions');
      expect(plan).toHaveProperty('coverage_targets');
      expect(plan).toHaveProperty('quality_gates');
      
      // Validate Phase 1 (BA Requirements)
      const phase1 = plan.phases[0];
      expect(phase1.phase_number).toBe(1);
      expect(phase1.tool_name).toBe('ba_analyze_requirements');
      expect(phase1.depends_on).toBeNull();
      expect(phase1.tool_input).toHaveProperty('project_name', input.project_name);
      
      // Validate Phase 2 (Architecture) depends on Phase 1
      const phase2 = plan.phases[1];
      expect(phase2.phase_number).toBe(2);
      expect(phase2.tool_name).toBe('techlead_design_architecture');
      expect(phase2.depends_on).toEqual(['Phase 1']);
      expect(phase2.tool_input.user_stories).toContain('{{PHASE_1_OUTPUT.user_stories}}');
      
      // Validate Phase 3 (Threat Model) depends on Phase 2
      const phase3 = plan.phases[2];
      expect(phase3.phase_number).toBe(3);
      expect(phase3.tool_name).toBe('security_threat_model');
      expect(phase3.depends_on).toEqual(['Phase 2']);
      
      // Validate all phases have expected_output
      plan.phases.forEach((phase: any) => {
        expect(phase).toHaveProperty('expected_output');
        expect(phase.expected_output).toHaveProperty('format', 'json');
        expect(phase.expected_output).toHaveProperty('required_fields');
        expect(Array.isArray(phase.expected_output.required_fields)).toBe(true);
      });
    });

    it('should include placeholder system for data flow', async () => {
      const { orchestrateSSDLCPipeline } = await import('../../src/tools/orchestration/orchestrate-pipeline-v2.js');
      
      const input = {
        project_name: "OAuth2 Server",
        project_description: "Enterprise OAuth2 provider",
        business_goals: ["Secure auth"],
        tech_stack: ["Python"],
        team_size: 5,
        sprint_duration: 2
      };

      const result = await orchestrateSSDLCPipeline(input);
      const plan = JSON.parse(result.content[0].text);
      
      // Check that Phase 2 references Phase 1 output
      const phase2 = plan.phases.find((p: any) => p.phase_number === 2);
      const phase2InputStr = JSON.stringify(phase2.tool_input);
      expect(phase2InputStr).toContain('{{PHASE_1_OUTPUT');
      
      // Check that Phase 3 references Phase 2 output
      const phase3 = plan.phases.find((p: any) => p.phase_number === 3);
      const phase3InputStr = JSON.stringify(phase3.tool_input);
      expect(phase3InputStr).toContain('{{PHASE_2_OUTPUT');
    });

    it('should include coverage targets', async () => {
      const { orchestrateSSDLCPipeline } = await import('../../src/tools/orchestration/orchestrate-pipeline-v2.js');
      
      const input = {
        project_name: "Test",
        project_description: "Test",
        business_goals: [],
        tech_stack: [],
        team_size: 4,
        sprint_duration: 2
      };

      const result = await orchestrateSSDLCPipeline(input);
      const plan = JSON.parse(result.content[0].text);
      
      expect(plan.coverage_targets).toMatchObject({
        requirements: expect.stringMatching(/90-95%/),
        security: expect.stringMatching(/85-95%/),
        architecture: expect.stringMatching(/85-90%/),
        pseudocode: expect.stringMatching(/80-90%/),
        testing: expect.stringMatching(/85-90%/)
      });
    });

    it('should include quality gates for each phase', async () => {
      const { orchestrateSSDLCPipeline } = await import('../../src/tools/orchestration/orchestrate-pipeline-v2.js');
      
      const input = {
        project_name: "Test",
        project_description: "Test",
        business_goals: [],
        tech_stack: [],
        team_size: 4,
        sprint_duration: 2
      };

      const result = await orchestrateSSDLCPipeline(input);
      const plan = JSON.parse(result.content[0].text);
      
      expect(plan.quality_gates).toHaveProperty('phase_1');
      expect(plan.quality_gates).toHaveProperty('phase_2');
      expect(plan.quality_gates).toHaveProperty('phase_3');
      
      expect(Array.isArray(plan.quality_gates.phase_1)).toBe(true);
      expect(plan.quality_gates.phase_1.length).toBeGreaterThan(0);
    });
  });

  describe('Execution Instructions', () => {
    it('should provide clear execution instructions for Claude', async () => {
      const { orchestrateSSDLCPipeline } = await import('../../src/tools/orchestration/orchestrate-pipeline-v2.js');
      
      const input = {
        project_name: "Test",
        project_description: "Test",
        business_goals: [],
        tech_stack: [],
        team_size: 4,
        sprint_duration: 2
      };

      const result = await orchestrateSSDLCPipeline(input);
      const plan = JSON.parse(result.content[0].text);
      
      expect(plan.execution_instructions).toBeDefined();
      expect(typeof plan.execution_instructions).toBe('string');
      expect(plan.execution_instructions.length).toBeGreaterThan(50);
      
      // Should mention tool execution
      expect(plan.execution_instructions.toLowerCase()).toMatch(/tool|phase|execute|output/);
    });
  });

  describe('Phase Dependency Chain', () => {
    it('should create valid dependency chain across 7 phases', async () => {
      const { orchestrateSSDLCPipeline } = await import('../../src/tools/orchestration/orchestrate-pipeline-v2.js');
      
      const input = {
        project_name: "Complex System",
        project_description: "Multi-tier system",
        business_goals: ["Security", "Scale"],
        tech_stack: ["Node.js", "PostgreSQL"],
        team_size: 10,
        sprint_duration: 2
      };

      const result = await orchestrateSSDLCPipeline(input);
      const plan = JSON.parse(result.content[0].text);
      
      // Phase 1: No dependencies
      expect(plan.phases[0].depends_on).toBeNull();
      
      // Phase 2: Depends on Phase 1
      expect(plan.phases[1].depends_on).toEqual(['Phase 1']);
      
      // Phase 3: Depends on Phase 2
      expect(plan.phases[2].depends_on).toEqual(['Phase 2']);
      
      // Phase 4: Depends on Phase 2 and 3
      expect(plan.phases[3].depends_on).toContain('Phase 2');
      expect(plan.phases[3].depends_on).toContain('Phase 3');
      
      // Phase 5: Depends on Phase 1 and 3
      expect(plan.phases[4].depends_on).toContain('Phase 1');
      expect(plan.phases[4].depends_on).toContain('Phase 3');
      
      // Phase 6: Depends on Phase 4
      expect(plan.phases[5].depends_on).toContain('Phase 4');
      
      // Phase 7: Depends on all previous phases
      expect(plan.phases[6].depends_on).toContain('Phase 1');
      expect(plan.phases[6].depends_on).toContain('Phase 5');
    });
  });

  describe('Real-World Project Scenarios', () => {
    it('should handle healthcare project orchestration', async () => {
      const { orchestrateSSDLCPipeline } = await import('../../src/tools/orchestration/orchestrate-pipeline-v2.js');
      
      const input = {
        project_name: "Healthcare EHR System",
        project_description: "Electronic health records with HIPAA compliance, patient portal, doctor dashboard, appointment scheduling, and prescription management",
        business_goals: [
          "HIPAA compliance",
          "High availability (99.99%)",
          "Secure patient data",
          "Fast response times"
        ],
        tech_stack: ["Node.js", "React", "PostgreSQL", "Redis", "Docker"],
        team_size: 12,
        sprint_duration: 2
      };

      const result = await orchestrateSSDLCPipeline(input);
      const plan = JSON.parse(result.content[0].text);
      
      expect(plan.phases).toHaveLength(7);
      
      // BA phase should include HIPAA requirements
      const baPhase = plan.phases[0];
      expect(JSON.stringify(baPhase).toLowerCase()).toMatch(/hipaa|compliance|patient/);
      
      // Security phase should reference healthcare threats
      const securityPhase = plan.phases[2];
      expect(securityPhase.tool_name).toBe('security_threat_model');
    });

    it('should handle OAuth2 server orchestration', async () => {
      const { orchestrateSSDLCPipeline } = await import('../../src/tools/orchestration/orchestrate-pipeline-v2.js');
      
      const input = {
        project_name: "OAuth2 Authorization Server",
        project_description: "Enterprise OAuth2/OpenID Connect provider with client registration, multiple grant types, JWT tokens, refresh tokens, and security monitoring",
        business_goals: [
          "OAuth 2.1 compliance",
          "OpenID Connect support",
          "High security",
          "Scalable to 100K users"
        ],
        tech_stack: ["Python", "FastAPI", "PostgreSQL", "Redis"],
        team_size: 6,
        sprint_duration: 2
      };

      const result = await orchestrateSSDLCPipeline(input);
      const plan = JSON.parse(result.content[0].text);
      
      expect(plan.phases).toHaveLength(7);
      
      // Should propagate OAuth context through phases
      const planStr = JSON.stringify(plan).toLowerCase();
      expect(planStr).toMatch(/oauth|token|authorization/);
    });

    it('should handle financial trading platform orchestration', async () => {
      const { orchestrateSSDLCPipeline } = await import('../../src/tools/orchestration/orchestrate-pipeline-v2.js');
      
      const input = {
        project_name: "Financial Trading Platform",
        project_description: "Real-time trading system with market data streaming, order execution, risk management, compliance monitoring, and audit logging",
        business_goals: [
          "SEC compliance",
          "Sub-millisecond latency",
          "High availability (99.999%)",
          "Comprehensive audit logging"
        ],
        tech_stack: ["C++", "Python", "PostgreSQL", "Kafka", "Redis"],
        team_size: 15,
        sprint_duration: 2
      };

      const result = await orchestrateSSDLCPipeline(input);
      const plan = JSON.parse(result.content[0].text);
      
      expect(plan.phases).toHaveLength(7);
      
      // Should capture security and compliance requirements
      const planStr = JSON.stringify(plan).toLowerCase();
      expect(planStr).toMatch(/compliance|audit|security/);
    });
  });

  describe('Error Handling', () => {
    it('should reject invalid input schema', async () => {
      const { orchestrateSSDLCPipeline } = await import('../../src/tools/orchestration/orchestrate-pipeline-v2.js');
      
      const invalidInput = {
        wrong_field: "test"
      };

      await expect(orchestrateSSDLCPipeline(invalidInput)).rejects.toThrow();
    });

    it('should handle minimal team size', async () => {
      const { orchestrateSSDLCPipeline } = await import('../../src/tools/orchestration/orchestrate-pipeline-v2.js');
      
      const input = {
        project_name: "Small Project",
        project_description: "Solo developer project",
        business_goals: [],
        tech_stack: [],
        team_size: 1,
        sprint_duration: 1
      };

      const result = await orchestrateSSDLCPipeline(input);
      const plan = JSON.parse(result.content[0].text);
      
      // Should still generate full plan
      expect(plan.phases).toHaveLength(7);
    });
  });

  describe('Plan Validation', () => {
    it('should ensure all phases have unique phase numbers', async () => {
      const { orchestrateSSDLCPipeline } = await import('../../src/tools/orchestration/orchestrate-pipeline-v2.js');
      
      const input = {
        project_name: "Test",
        project_description: "Test",
        business_goals: [],
        tech_stack: [],
        team_size: 4,
        sprint_duration: 2
      };

      const result = await orchestrateSSDLCPipeline(input);
      const plan = JSON.parse(result.content[0].text);
      
      const phaseNumbers = plan.phases.map((p: any) => p.phase_number);
      const uniqueNumbers = new Set(phaseNumbers);
      
      expect(phaseNumbers.length).toBe(uniqueNumbers.size);
    });

    it('should ensure all tool names are valid', async () => {
      const { orchestrateSSDLCPipeline } = await import('../../src/tools/orchestration/orchestrate-pipeline-v2.js');
      
      const input = {
        project_name: "Test",
        project_description: "Test",
        business_goals: [],
        tech_stack: [],
        team_size: 4,
        sprint_duration: 2
      };

      const result = await orchestrateSSDLCPipeline(input);
      const plan = JSON.parse(result.content[0].text);
      
      const validToolNames = [
        'ba_analyze_requirements',
        'techlead_design_architecture',
        'security_threat_model',
        'techlead_generate_pseudocode',
        'qa_design_test_strategy',
        'devops_generate_pipeline',
        'pm_create_sprint_plan'
      ];
      
      plan.phases.forEach((phase: any) => {
        expect(validToolNames).toContain(phase.tool_name);
      });
    });

    it('should ensure no circular dependencies', async () => {
      const { orchestrateSSDLCPipeline } = await import('../../src/tools/orchestration/orchestrate-pipeline-v2.js');
      
      const input = {
        project_name: "Test",
        project_description: "Test",
        business_goals: [],
        tech_stack: [],
        team_size: 4,
        sprint_duration: 2
      };

      const result = await orchestrateSSDLCPipeline(input);
      const plan = JSON.parse(result.content[0].text);
      
      plan.phases.forEach((phase: any) => {
        if (phase.depends_on) {
          phase.depends_on.forEach((dep: string) => {
            const depNumber = parseInt(dep.replace('Phase ', ''));
            expect(depNumber).toBeLessThan(phase.phase_number);
          });
        }
      });
    });
  });
});

