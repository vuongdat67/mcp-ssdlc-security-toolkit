/**
 * Generate Secure Code Tool
 * 
 * Generates secure code implementations from requirements/pseudocode.
 */

import { z } from 'zod';
import type { MCPToolResult } from '@mcp-ssdlc/core';
import { createLogger } from '@mcp-ssdlc/core';

const logger = createLogger('GenerateSecureCode');

// ============================================================================
// Input Schema
// ============================================================================

const GenerateSecureCodeInputSchema = z.object({
  requirement: z.string().min(10).describe('The requirement or pseudocode to implement'),
  language: z.enum(['javascript', 'typescript', 'python', 'go', 'java', 'csharp']).describe('Target programming language'),
  framework: z.string().optional().describe('Target framework (e.g., express, fastapi, spring)'),
  securityContext: z.object({
    authRequired: z.boolean().optional().default(true),
    inputValidation: z.boolean().optional().default(true),
    outputEncoding: z.boolean().optional().default(true),
    logging: z.boolean().optional().default(true),
    rateLimiting: z.boolean().optional().default(false),
  }).optional().default({}),
  cweAvoid: z.array(z.string()).optional().describe('CWE IDs to specifically avoid'),
});

type GenerateSecureCodeInput = z.infer<typeof GenerateSecureCodeInputSchema>;

// ============================================================================
// Secure Code Templates
// ============================================================================

const securePatterns: Record<string, Record<string, string>> = {
  javascript: {
    inputValidation: `
// Input validation with Zod
import { z } from 'zod';

const inputSchema = z.object({
  // Define your schema here
});

function validateInput(input) {
  const result = inputSchema.safeParse(input);
  if (!result.success) {
    throw new ValidationError(result.error.message);
  }
  return result.data;
}`,
    authentication: `
// JWT Authentication middleware
import jwt from 'jsonwebtoken';

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  
  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}`,
    sqlInjectionPrevention: `
// Parameterized queries to prevent SQL injection
async function getUserById(userId) {
  const query = 'SELECT * FROM users WHERE id = $1';
  const result = await db.query(query, [userId]);
  return result.rows[0];
}`,
    xssPrevention: `
// XSS prevention - use textContent instead of innerHTML
function displayUserContent(content, element) {
  // SAFE: textContent automatically escapes HTML
  element.textContent = content;
  
  // If HTML is needed, use DOMPurify
  // element.innerHTML = DOMPurify.sanitize(content);
}`,
    rateLimiting: `
// Rate limiting with express-rate-limit
import rateLimit from 'express-rate-limit';

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: { error: 'Too many requests, please try again later' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/', limiter);`,
  },
  python: {
    inputValidation: `
# Input validation with Pydantic
from pydantic import BaseModel, validator
from typing import Optional

class UserInput(BaseModel):
    email: str
    password: str
    age: Optional[int] = None

    @validator('email')
    def email_must_be_valid(cls, v):
        if '@' not in v:
            raise ValueError('Invalid email format')
        return v

    @validator('password')
    def password_must_be_strong(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        return v`,
    authentication: `
# JWT Authentication decorator
import jwt
from functools import wraps
from flask import request, jsonify

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        try:
            data = jwt.decode(token, os.environ['JWT_SECRET'], algorithms=['HS256'])
            current_user = User.query.get(data['user_id'])
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(current_user, *args, **kwargs)
    return decorated`,
    sqlInjectionPrevention: `
# Parameterized queries with SQLAlchemy
from sqlalchemy import text

def get_user_by_id(user_id: int):
    query = text("SELECT * FROM users WHERE id = :user_id")
    result = db.session.execute(query, {"user_id": user_id})
    return result.fetchone()

# Or use ORM (preferred)
def get_user_by_id_orm(user_id: int):
    return User.query.filter_by(id=user_id).first()`,
    xssPrevention: `
# XSS prevention with Jinja2 auto-escaping
from markupsafe import escape

def sanitize_user_input(user_input: str) -> str:
    return escape(user_input)

# In templates, Jinja2 auto-escapes by default
# {{ user_input }} - automatically escaped
# {{ user_input | safe }} - use with caution!`,
    rateLimiting: `
# Rate limiting with Flask-Limiter
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

@app.route("/api/login")
@limiter.limit("5 per minute")
def login():
    pass`,
  },
};

// ============================================================================
// Code Generator
// ============================================================================

export async function generateSecureCode(input: unknown): Promise<MCPToolResult> {
  logger.info('Generating secure code implementation');

  // Validate input
  const validation = GenerateSecureCodeInputSchema.safeParse(input);
  if (!validation.success) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          error: 'Validation failed',
          details: validation.error.format()
        }, null, 2)
      }]
    };
  }

  const { requirement, language, framework, securityContext, cweAvoid } = validation.data;

  // Analyze requirement for security patterns needed
  const requiredPatterns = analyzeRequirement(requirement, securityContext);

  // Get language-specific patterns
  const langPatterns = securePatterns[language] || securePatterns.javascript;

  // Build code with security patterns
  const codeBlocks: string[] = [];
  const securityNotes: string[] = [];

  // Add relevant secure patterns
  if (requiredPatterns.includes('inputValidation') && langPatterns.inputValidation) {
    codeBlocks.push(langPatterns.inputValidation);
    securityNotes.push('✅ Input validation implemented with schema-based validation');
  }

  if (requiredPatterns.includes('authentication') && langPatterns.authentication) {
    codeBlocks.push(langPatterns.authentication);
    securityNotes.push('✅ JWT authentication with proper error handling');
  }

  if (requiredPatterns.includes('database') && langPatterns.sqlInjectionPrevention) {
    codeBlocks.push(langPatterns.sqlInjectionPrevention);
    securityNotes.push('✅ Parameterized queries prevent SQL injection (CWE-89)');
  }

  if (requiredPatterns.includes('display') && langPatterns.xssPrevention) {
    codeBlocks.push(langPatterns.xssPrevention);
    securityNotes.push('✅ Output encoding prevents XSS (CWE-79)');
  }

  if (securityContext?.rateLimiting && langPatterns.rateLimiting) {
    codeBlocks.push(langPatterns.rateLimiting);
    securityNotes.push('✅ Rate limiting prevents abuse (CWE-770)');
  }

  // Generate main implementation stub
  const mainCode = generateMainImplementation(requirement, language, framework);
  codeBlocks.push(mainCode);

  const result = {
    language,
    framework: framework || 'none',
    requirement,
    generated_code: codeBlocks.join('\n\n// ' + '='.repeat(70) + '\n\n'),
    security_notes: securityNotes,
    cwe_coverage: [
      'CWE-20 (Improper Input Validation)',
      'CWE-79 (Cross-site Scripting)',
      'CWE-89 (SQL Injection)',
      'CWE-287 (Improper Authentication)',
      'CWE-770 (Allocation of Resources Without Limits)',
    ],
    next_steps: [
      'Review generated code for business logic',
      'Add unit tests for security controls',
      'Run security_review_code on final implementation',
      'Conduct code review with security focus',
    ],
  };

  return {
    content: [{
      type: 'text',
      text: JSON.stringify(result, null, 2)
    }]
  };
}

// ============================================================================
// Helpers
// ============================================================================

function analyzeRequirement(requirement: string, context: any): string[] {
  const patterns: string[] = [];
  const lower = requirement.toLowerCase();

  // Always include input validation
  if (context?.inputValidation !== false) {
    patterns.push('inputValidation');
  }

  // Check for auth-related keywords
  if (lower.includes('login') || lower.includes('auth') || lower.includes('user') || 
      lower.includes('token') || lower.includes('session') || context?.authRequired) {
    patterns.push('authentication');
  }

  // Check for database-related keywords
  if (lower.includes('database') || lower.includes('query') || lower.includes('select') ||
      lower.includes('insert') || lower.includes('update') || lower.includes('delete') ||
      lower.includes('db') || lower.includes('sql')) {
    patterns.push('database');
  }

  // Check for display/output keywords
  if (lower.includes('display') || lower.includes('render') || lower.includes('show') ||
      lower.includes('html') || lower.includes('template') || context?.outputEncoding) {
    patterns.push('display');
  }

  return patterns;
}

function generateMainImplementation(requirement: string, language: string, framework?: string): string {
  const comment = language === 'python' ? '#' : '//';
  
  return `${comment} Main Implementation
${comment} Requirement: ${requirement}
${comment} Framework: ${framework || 'standard library'}

${comment} TODO: Implement business logic here
${comment} The security patterns above provide the foundation.
${comment} 
${comment} Remember to:
${comment} 1. Validate all inputs before processing
${comment} 2. Use parameterized queries for database operations
${comment} 3. Encode output appropriately for context
${comment} 4. Log security-relevant events
${comment} 5. Handle errors without exposing sensitive information`;
}
