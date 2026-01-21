import { describe, it, expect } from 'vitest';
import { baAnalyzeRequirements } from '../src/tools/requirements/analyze-requirements';

describe('BA Tool: Analyze Requirements', () => {
  it('should generate user stories from project description', async () => {
    const input = {
      project_description: 'OAuth2 authorization server for securing internal microservices with JWT tokens and role-based access control',
      stakeholders: ['Backend developers', 'Security team', 'DevOps engineers'],
      business_goals: ['Secure authentication', 'Scalable to 10,000 users', 'OAuth2 spec compliance']
    };

    const result = await baAnalyzeRequirements(input);

    expect(result.content).toBeDefined();
    expect(result.content.length).toBeGreaterThan(0);
    expect(result.content[0].type).toBe('text');
    
    const output = result.content[0].text;
    expect(output).toContain('User Stories');
    expect(output).toContain('US-');
    expect(output).toContain('Acceptance Criteria');
    expect(output).toContain('Security Considerations');
  });

  it('should reject invalid input', async () => {
    const input = {
      project_description: 'short',
      stakeholders: [],
      business_goals: []
    };

    await expect(baAnalyzeRequirements(input)).rejects.toThrow('Validation failed');
  });

  it('should prioritize security-related stories as High', async () => {
    const input = {
      project_description: 'Authentication system with encryption and audit logging',
      stakeholders: ['Users'],
      business_goals: ['Security']
    };

    const result = await baAnalyzeRequirements(input);
    const output = result.content[0].text;

    expect(output).toContain('**Priority:** High');
    expect(output).toContain('authentication');
  });
});
