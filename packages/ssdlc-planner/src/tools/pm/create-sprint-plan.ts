/**
 * PM Tool: Create Sprint Plan
 * 
 * Generates sprint planning with task breakdown and timeline
 */

import { z } from "zod";
import { createLogger } from "@mcp-ssdlc/core";

const logger = createLogger("pm-create-sprint-plan");

// Priority normalization helper - accepts P0/P1/P2/P3 or High/Medium/Low/Critical
const normalizePriority = (priority: string): "P0" | "P1" | "P2" | "P3" => {
  const normalized = priority.toLowerCase().trim();
  const mapping: Record<string, "P0" | "P1" | "P2" | "P3"> = {
    // Standard formats
    'p0': 'P0', 'p1': 'P1', 'p2': 'P2', 'p3': 'P3',
    // Common alternatives
    'critical': 'P0', 'high': 'P0', 'medium': 'P1', 'low': 'P2', 'lowest': 'P3',
    // Numbered formats
    '0': 'P0', '1': 'P1', '2': 'P2', '3': 'P3',
    // Word formats
    'urgent': 'P0', 'normal': 'P1', 'minor': 'P2', 'trivial': 'P3',
  };
  return mapping[normalized] || 'P2'; // Default to P2 if unknown
};

// Flexible priority schema that accepts multiple formats
const FlexiblePrioritySchema = z.string().transform(normalizePriority);

// Make all fields optional with defaults for standalone usage
const CreateSprintPlanSchema = z.object({
  project_name: z.string().optional().default("Secure Application"),
  sprint_duration: z.number().min(1).max(4).optional().default(2), // weeks
  team_size: z.number().min(1).optional().default(5),
  user_stories: z.array(z.object({
    id: z.string(),
    title: z.string(),
    priority: FlexiblePrioritySchema,
    story_points: z.number().optional(),
  })).optional().default([
    { id: "US-001", title: "User Authentication", priority: "P0", story_points: 8 },
    { id: "US-002", title: "Access Control", priority: "P0", story_points: 5 },
    { id: "US-003", title: "Data Encryption", priority: "P1", story_points: 5 },
    { id: "US-004", title: "Audit Logging", priority: "P1", story_points: 3 },
    { id: "US-005", title: "Input Validation", priority: "P2", story_points: 3 },
  ]),
  team_velocity: z.number().optional(), // story points per sprint
});

export async function pmCreateSprintPlan(args: unknown) {
  try {
    // Handle empty input
    const normalizedArgs = (args && typeof args === 'object' && Object.keys(args).length > 0)
      ? args
      : {};

    const input = CreateSprintPlanSchema.parse(normalizedArgs);

    logger.info(`Creating sprint plan for: ${input.project_name}`);

    // Calculate velocity if not provided
    const velocity = input.team_velocity || calculateDefaultVelocity(input.team_size, input.sprint_duration);

    // Prioritize and select stories
    const sprintBacklog = selectSprintBacklog(input.user_stories, velocity);

    // Break down into tasks
    const taskBreakdown = generateTaskBreakdown(sprintBacklog);

    // Create timeline
    const timeline = generateTimeline(input.sprint_duration, taskBreakdown);

    const output = `# Sprint Plan: ${input.project_name}
Generated: ${new Date().toISOString()}
Sprint Duration: ${input.sprint_duration} weeks
Team Size: ${input.team_size} members
Team Velocity: ${velocity} story points

## Sprint Goal

${generateSprintGoal(sprintBacklog)}

## Sprint Backlog

${sprintBacklog.map((story, i) => `
### ${i + 1}. ${story.title} (${story.id})
- **Priority**: ${story.priority}
- **Story Points**: ${story.story_points || 'TBD'}
- **Tasks**: ${getTaskCount(story, taskBreakdown)} tasks
- **Estimated Days**: ${estimateDays(story.story_points || 0)}
`).join('\n')}

**Total Story Points**: ${sprintBacklog.reduce((sum, s) => sum + (s.story_points || 0), 0)}

## Task Breakdown

${taskBreakdown.map(task => `
### ${task.story_id}: ${task.task_name}
- **Assignee**: ${task.assignee}
- **Effort**: ${task.effort_hours}h
- **Dependencies**: ${task.dependencies.length > 0 ? task.dependencies.join(', ') : 'None'}
- **Type**: ${task.type}
`).join('\n')}

## Sprint Timeline

${timeline}

## Daily Schedule

### Week 1
- **Day 1 (Monday)**: Sprint Planning Meeting (2h)
  - Review sprint goal and backlog
  - Task breakdown and estimation
  - Team commitments

- **Days 2-5**: Development Sprint
  - Daily standup (15min)
  - Focus on P0 stories
  - Code reviews and testing

### Week ${input.sprint_duration === 1 ? '1 (continued)' : '2'}
- **Days ${input.sprint_duration === 1 ? '6-7' : '1-5'}**: Feature completion
  - Integration testing
  - Security review
  - Documentation

${input.sprint_duration > 1 ? `### Week ${input.sprint_duration}
- **Days 1-3**: Final testing and bug fixes
- **Day 4**: Sprint Review (1h)
  - Demo completed features
  - Stakeholder feedback
- **Day 5**: Sprint Retrospective (1h)
  - What went well
  - What to improve
  - Action items
` : ''}

## Success Metrics

- **Velocity Achievement**: ${velocity} story points completed
- **Code Coverage**: >80%
- **Bug Count**: <5 critical/high bugs
- **On-Time Delivery**: All P0 stories completed

## Risks & Mitigation

${generateRisks(sprintBacklog, input.team_size)}

## Definition of Done

- [ ] Code reviewed by at least 1 team member
- [ ] Unit tests written and passing (>80% coverage)
- [ ] Integration tests passing
- [ ] Security review completed (no HIGH/CRITICAL issues)
- [ ] Documentation updated
- [ ] Deployed to staging environment
- [ ] Product owner acceptance

## Team Capacity

- **Total Developer Hours**: ${input.team_size * input.sprint_duration * 40} hours
- **Available for Development**: ${Math.floor(input.team_size * input.sprint_duration * 40 * 0.7)} hours (30% buffer for meetings, reviews)
- **Allocated Hours**: ${calculateAllocatedHours(taskBreakdown)} hours

---

**Next Steps:**
1. Conduct sprint planning meeting
2. Assign tasks to team members
3. Set up sprint board (Jira/GitHub Projects)
4. Schedule daily standups
5. Configure sprint tracking
`;

    return {
      content: [
        {
          type: "text",
          text: output,
        },
      ],
    };
  } catch (error) {
    if (error instanceof z.ZodError) {
      throw new Error(`Validation failed: ${error.errors.map(e => e.message).join(', ')}`);
    }
    throw error;
  }
}

function calculateDefaultVelocity(teamSize: number, sprintDuration: number): number {
  // Assume 5-8 story points per developer per week
  const pointsPerDevPerWeek = 6;
  return teamSize * sprintDuration * pointsPerDevPerWeek;
}

function selectSprintBacklog(
  stories: Array<{ id: string; title: string; priority: string; story_points?: number }>,
  velocity: number
): Array<{ id: string; title: string; priority: string; story_points: number }> {
  // Prioritize and select stories that fit velocity
  const prioritized = stories
    .map(s => ({ ...s, story_points: s.story_points || estimateStoryPoints(s.title) }))
    .sort((a, b) => {
      const priorityOrder: Record<string, number> = { P0: 0, P1: 1, P2: 2, P3: 3 };
      return priorityOrder[a.priority] - priorityOrder[b.priority];
    });

  const selected: typeof prioritized = [];
  let totalPoints = 0;

  for (const story of prioritized) {
    if (totalPoints + story.story_points <= velocity) {
      selected.push(story);
      totalPoints += story.story_points;
    }
  }

  return selected;
}

function estimateStoryPoints(title: string): number {
  // Simple heuristic based on complexity keywords
  const complexity = title.toLowerCase();
  if (complexity.includes("complex") || complexity.includes("integration")) return 8;
  if (complexity.includes("implement") || complexity.includes("create")) return 5;
  if (complexity.includes("update") || complexity.includes("fix")) return 3;
  return 3; // default
}

function generateSprintGoal(stories: Array<{ title: string; priority: string }>): string {
  const p0Count = stories.filter(s => s.priority === "P0").length;
  return `Complete ${p0Count} critical user stories focusing on core functionality and security requirements. Establish foundation for ${stories.length - p0Count} additional features in upcoming sprints.`;
}

function generateTaskBreakdown(stories: Array<{ id: string; title: string; story_points: number }>): Array<{
  story_id: string;
  task_name: string;
  assignee: string;
  effort_hours: number;
  dependencies: string[];
  type: string;
}> {
  const tasks: ReturnType<typeof generateTaskBreakdown> = [];

  stories.forEach(story => {
    // Each story gets broken into tasks
    tasks.push(
      {
        story_id: story.id,
        task_name: `Design: ${story.title}`,
        assignee: "Tech Lead",
        effort_hours: Math.ceil(story.story_points * 0.5),
        dependencies: [],
        type: "Design"
      },
      {
        story_id: story.id,
        task_name: `Implement: ${story.title}`,
        assignee: "Developer",
        effort_hours: story.story_points * 2,
        dependencies: [`Design: ${story.title}`],
        type: "Development"
      },
      {
        story_id: story.id,
        task_name: `Test: ${story.title}`,
        assignee: "QA Engineer",
        effort_hours: Math.ceil(story.story_points * 1),
        dependencies: [`Implement: ${story.title}`],
        type: "Testing"
      },
      {
        story_id: story.id,
        task_name: `Security Review: ${story.title}`,
        assignee: "Security Engineer",
        effort_hours: Math.ceil(story.story_points * 0.5),
        dependencies: [`Implement: ${story.title}`],
        type: "Security"
      }
    );
  });

  return tasks;
}

function getTaskCount(
  story: { id: string },
  tasks: Array<{ story_id: string }>
): number {
  return tasks.filter(t => t.story_id === story.id).length;
}

function estimateDays(storyPoints: number): number {
  // 1 story point = ~0.5 days
  return Math.ceil(storyPoints * 0.5);
}

function generateTimeline(sprintDuration: number, tasks: Array<{ task_name: string; effort_hours: number; dependencies: string[] }>): string {
  return `\`\`\`mermaid
gantt
    title Sprint Timeline
    dateFormat YYYY-MM-DD
    section Design
    ${tasks.filter(t => t.task_name.startsWith('Design')).map(t =>
    `${t.task_name} :d${tasks.indexOf(t)}, 2024-01-01, ${Math.ceil(t.effort_hours / 8)}d`
  ).join('\n    ')}
    section Development
    ${tasks.filter(t => t.task_name.startsWith('Implement')).map(t =>
    `${t.task_name} :i${tasks.indexOf(t)}, after d${tasks.findIndex(x => x.dependencies.includes(t.task_name.replace('Implement', 'Design')))}, ${Math.ceil(t.effort_hours / 8)}d`
  ).join('\n    ')}
    section Testing
    ${tasks.filter(t => t.task_name.startsWith('Test')).slice(0, 3).map(t =>
    `${t.task_name} :t${tasks.indexOf(t)}, ${Math.ceil(t.effort_hours / 8)}d`
  ).join('\n    ')}
\`\`\``;
}

function calculateAllocatedHours(tasks: Array<{ effort_hours: number }>): number {
  return tasks.reduce((sum, t) => sum + t.effort_hours, 0);
}

function generateRisks(stories: Array<{ priority: string; story_points: number }>, teamSize: number): string {
  const risks = [];

  if (stories.some(s => s.story_points > 8)) {
    risks.push("**Large Stories**: Some stories >8 points may need further breakdown");
  }

  if (teamSize < 3) {
    risks.push("**Small Team**: Limited bandwidth for parallel work, dependencies may cause delays");
  }

  const totalPoints = stories.reduce((sum, s) => sum + s.story_points, 0);
  const expectedVelocity = teamSize * 2 * 6; // 2 weeks * 6 points/week
  if (totalPoints > expectedVelocity * 1.2) {
    risks.push("**Over-commitment**: Sprint backlog exceeds typical velocity by >20%");
  }

  if (risks.length === 0) {
    return "No major risks identified for this sprint.";
  }

  return risks.map((r, i) => `${i + 1}. ${r}`).join('\n');
}
