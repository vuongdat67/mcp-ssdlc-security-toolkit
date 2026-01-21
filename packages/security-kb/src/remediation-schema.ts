/**
 * Remediation Schema - Secure Coding Examples
 * Phase 6B: Language-specific remediation guidance
 */

import { Database } from 'sql.js';

export interface RemediationEntry {
  cwe_id: string;
  language: string;
  insecure_example: string;
  secure_example: string;
  explanation: string;
  references?: string[];
}

/**
 * Initialize remediation table in SQLite.
 */
export function initializeRemediationSchema(db: Database): void {
  db.run(`
    CREATE TABLE IF NOT EXISTS cwe_remediation (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      cwe_id TEXT NOT NULL,
      language TEXT NOT NULL,
      insecure_example TEXT NOT NULL,
      secure_example TEXT NOT NULL,
      explanation TEXT NOT NULL,
      references_json TEXT DEFAULT '[]',
      FOREIGN KEY (cwe_id) REFERENCES cwes(cwe_id),
      UNIQUE(cwe_id, language)
    )
  `);

  // Index for fast lookups
  db.run('CREATE INDEX IF NOT EXISTS idx_remediation_cwe ON cwe_remediation(cwe_id)');
  db.run('CREATE INDEX IF NOT EXISTS idx_remediation_language ON cwe_remediation(language)');
}

/**
 * Seed remediation table with secure coding examples.
 */
export function seedRemediationData(db: Database): number {
  const remediations = getRemediationExamples();
  
  const stmt = db.prepare(`
    INSERT OR REPLACE INTO cwe_remediation (cwe_id, language, insecure_example, secure_example, explanation, references_json)
    VALUES (?, ?, ?, ?, ?, ?)
  `);

  let inserted = 0;
  for (const rem of remediations) {
    try {
      stmt.bind([
        rem.cwe_id,
        rem.language,
        rem.insecure_example,
        rem.secure_example,
        rem.explanation,
        rem.references ? JSON.stringify(rem.references) : '[]'
      ]);
      stmt.step();
      stmt.reset();
      inserted++;
    } catch (error) {
      console.error(`Error inserting remediation for ${rem.cwe_id} (${rem.language}):`, error);
    }
  }

  stmt.free();
  return inserted;
}

/**
 * Get remediation examples for common vulnerabilities.
 * 
 * Coverage:
 * - CWE-79 (XSS) - JavaScript, Python
 * - CWE-89 (SQL Injection) - JavaScript, Python
 * - CWE-95 (Code Injection) - JavaScript, Python
 * - CWE-22 (Path Traversal) - JavaScript, Python
 * - CWE-502 (Deserialization) - Python, JavaScript
 * - CWE-78 (OS Command Injection) - Python
 */
function getRemediationExamples(): RemediationEntry[] {
  return [
    // ========== CWE-79: Cross-Site Scripting (XSS) ==========
    {
      cwe_id: 'CWE-79',
      language: 'javascript',
      insecure_example: `// INSECURE: Direct innerHTML assignment
element.innerHTML = userInput;

// INSECURE: document.write with user data
document.write(userInput);

// INSECURE: Unescaped response
res.send(\`<h1>\${username}</h1>\`);`,
      secure_example: `// SECURE: Use textContent for plain text
element.textContent = userInput;

// SECURE: Use DOM API with sanitization
const sanitized = DOMPurify.sanitize(userInput);
element.innerHTML = sanitized;

// SECURE: Template with auto-escaping (e.g., React, Vue)
return <h1>{username}</h1>;

// SECURE: Properly escaped response
res.send(escapeHtml(username));`,
      explanation: 'Never insert user input directly into HTML. Use textContent for plain text, or sanitize with DOMPurify/similar libraries. Modern frameworks (React, Vue) auto-escape by default. For server responses, always encode HTML entities.',
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html',
        'https://github.com/cure53/DOMPurify'
      ]
    },
    {
      cwe_id: 'CWE-79',
      language: 'python',
      insecure_example: `# INSECURE: Direct string formatting in templates
return f"<h1>{username}</h1>"

# INSECURE: Unescaped Jinja2
return render_template_string("<h1>{{ name }}</h1>", name=username)`,
      secure_example: `# SECURE: Use framework auto-escaping (Flask/Django)
from markupsafe import escape
return f"<h1>{escape(username)}</h1>"

# SECURE: Jinja2 auto-escapes by default
return render_template("page.html", name=username)

# SECURE: Explicitly mark safe only after sanitization
from bleach import clean
safe_html = clean(user_html, tags=['b', 'i', 'u'])
return Markup(safe_html)`,
      explanation: 'Use framework-provided auto-escaping (Flask, Django, Jinja2). Never mark user input as safe without sanitization. Use bleach or similar libraries for controlled HTML rendering.',
      references: [
        'https://flask.palletsprojects.com/en/2.3.x/security/#cross-site-scripting-xss'
      ]
    },

    // ========== CWE-89: SQL Injection ==========
    {
      cwe_id: 'CWE-89',
      language: 'javascript',
      insecure_example: `// INSECURE: String concatenation
const query = "SELECT * FROM users WHERE id = " + userId;
db.query(query);

// INSECURE: Template literals
const query = \`SELECT * FROM users WHERE name = '\${username}'\`;`,
      secure_example: `// SECURE: Parameterized queries (PostgreSQL)
const query = 'SELECT * FROM users WHERE id = $1';
db.query(query, [userId]);

// SECURE: Named parameters (MySQL)
const query = 'SELECT * FROM users WHERE name = ?';
db.query(query, [username]);

// SECURE: ORM with safe queries (TypeORM, Sequelize)
const user = await User.findOne({ where: { id: userId } });`,
      explanation: 'Always use parameterized queries or prepared statements. Never concatenate user input into SQL. Use ORM query builders (TypeORM, Sequelize) which provide automatic parameterization.',
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'
      ]
    },
    {
      cwe_id: 'CWE-89',
      language: 'python',
      insecure_example: `# INSECURE: String formatting
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)

# INSECURE: String concatenation
query = "SELECT * FROM users WHERE name = '" + username + "'"`,
      secure_example: `# SECURE: Parameterized queries (sqlite3)
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))

# SECURE: Named parameters (psycopg2)
query = "SELECT * FROM users WHERE name = %(name)s"
cursor.execute(query, {'name': username})

# SECURE: ORM (SQLAlchemy)
user = session.query(User).filter_by(id=user_id).first()`,
      explanation: 'Use parameterized queries with ? or named placeholders. Python DB-API automatically escapes parameters. For complex queries, use SQLAlchemy ORM which prevents injection by design.',
      references: [
        'https://bobby-tables.com/python'
      ]
    },

    // ========== CWE-95: Code Injection ==========
    {
      cwe_id: 'CWE-95',
      language: 'javascript',
      insecure_example: `// INSECURE: eval with user input
eval(userInput);

// INSECURE: Function constructor
new Function(userInput)();

// INSECURE: setTimeout with string
setTimeout(userInput, 1000);`,
      secure_example: `// SECURE: Parse JSON safely
const data = JSON.parse(userInput);

// SECURE: Use safe alternatives
// Instead of eval for math: use math.js or expr-eval
import { evaluate } from 'mathjs';
const result = evaluate(userInput); // Still validate input!

// SECURE: setTimeout with function
setTimeout(() => safeFunction(), 1000);

// SECURE: Use a sandbox if dynamic execution is required
import { VM } from 'vm2';
const vm = new VM({ timeout: 1000, sandbox: {} });
vm.run(userInput);`,
      explanation: 'Never use eval(), Function(), or setTimeout/setInterval with strings. For JSON, use JSON.parse(). For math expressions, use safe libraries. If dynamic code is absolutely required, use a proper sandbox (vm2, isolated-vm).',
      references: [
        'https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval#never_use_eval!'
      ]
    },
    {
      cwe_id: 'CWE-95',
      language: 'python',
      insecure_example: `# INSECURE: eval with user input
result = eval(user_expression)

# INSECURE: exec with user input
exec(user_code)

# INSECURE: compile + exec
code = compile(user_input, '<string>', 'exec')
exec(code)`,
      secure_example: `# SECURE: Use ast.literal_eval for safe data structures
import ast
data = ast.literal_eval(user_input)  # Only parses literals

# SECURE: Safe math expression evaluation
from asteval import Interpreter
aeval = Interpreter()
result = aeval(user_expression)

# SECURE: JSON parsing
import json
data = json.loads(user_input)

# If dynamic code is required: RestrictedPython (with extreme caution)
from RestrictedPython import compile_restricted
# Define safe globals/locals carefully`,
      explanation: 'Never use eval() or exec() with user input. Use ast.literal_eval for safe data parsing (only literals). For math expressions, use asteval. If dynamic code is unavoidable, use RestrictedPython with very careful configuration.',
      references: [
        'https://docs.python.org/3/library/ast.html#ast.literal_eval'
      ]
    },

    // ========== CWE-78: OS Command Injection ==========
    {
      cwe_id: 'CWE-78',
      language: 'python',
      insecure_example: `# INSECURE: shell=True with user input
import subprocess
subprocess.call(f"ls {user_path}", shell=True)

# INSECURE: os.system with user input
import os
os.system(f"rm {filename}")`,
      secure_example: `# SECURE: Use argument list with shell=False
import subprocess
subprocess.run(['ls', user_path], shell=False, check=True)

# SECURE: Use pathlib for file operations (no shell)
from pathlib import Path
Path(filename).unlink()

# SECURE: Validate input with allowlist
import shlex
safe_path = shlex.quote(user_path)  # Escape shell metacharacters
subprocess.run(f"ls {safe_path}", shell=True, check=True)`,
      explanation: 'Always use subprocess with argument lists and shell=False. Avoid os.system entirely. If shell=True is required, validate input against allowlist and use shlex.quote() to escape shell metacharacters.',
      references: [
        'https://docs.python.org/3/library/subprocess.html#security-considerations'
      ]
    },

    // ========== CWE-22: Path Traversal ==========
    {
      cwe_id: 'CWE-22',
      language: 'javascript',
      insecure_example: `// INSECURE: Direct path concatenation
const filePath = './uploads/' + req.query.filename;
fs.readFile(filePath);

// INSECURE: No validation
const filePath = path.join(__dirname, 'files', userPath);`,
      secure_example: `// SECURE: Validate and sanitize path
const path = require('path');
const basePath = '/safe/upload/dir';
const safePath = path.normalize(path.join(basePath, filename));

// Ensure the resolved path is within basePath
if (!safePath.startsWith(basePath)) {
  throw new Error('Invalid path');
}

// SECURE: Use allowlist of filenames
const allowedFiles = ['file1.txt', 'file2.txt'];
if (!allowedFiles.includes(filename)) {
  throw new Error('File not allowed');
}`,
      explanation: 'Never trust user-provided paths. Use path.normalize() and validate the resolved path stays within allowed directory. Better: use allowlist of allowed filenames, not paths.',
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html'
      ]
    },
    {
      cwe_id: 'CWE-22',
      language: 'python',
      insecure_example: `# INSECURE: Direct path joining
file_path = os.path.join('/uploads', user_filename)
with open(file_path, 'r') as f:
    content = f.read()

# INSECURE: No traversal check
file_path = f"./files/{user_path}"`,
      secure_example: `# SECURE: Resolve and validate path
from pathlib import Path

base_dir = Path('/safe/upload/dir').resolve()
requested_path = (base_dir / user_filename).resolve()

# Ensure path is within base_dir
if not requested_path.is_relative_to(base_dir):
    raise ValueError('Path traversal detected')

with open(requested_path, 'r') as f:
    content = f.read()

# SECURE: Use allowlist
allowed_files = {'file1.txt', 'file2.txt'}
if user_filename not in allowed_files:
    raise ValueError('File not allowed')`,
      explanation: 'Use pathlib.Path.resolve() to normalize paths and check if resolved path is within allowed base directory using is_relative_to(). Prefer allowlist approach over path validation.',
      references: [
        'https://docs.python.org/3/library/pathlib.html'
      ]
    },

    // ========== CWE-502: Deserialization ==========
    {
      cwe_id: 'CWE-502',
      language: 'python',
      insecure_example: `# INSECURE: pickle with untrusted data
import pickle
data = pickle.loads(user_data)

# INSECURE: yaml.load with untrusted data
import yaml
config = yaml.load(user_config)`,
      secure_example: `# SECURE: Use JSON (no code execution)
import json
data = json.loads(user_data)

# SECURE: yaml.safe_load (no arbitrary objects)
import yaml
config = yaml.safe_load(user_config)

# If pickle is required: sign and verify
import hmac
import pickle

def secure_pickle_loads(data, secret_key):
    signature, pickled = data.split(b':', 1)
    expected_sig = hmac.new(secret_key, pickled, 'sha256').digest()
    if not hmac.compare_digest(signature, expected_sig):
        raise ValueError('Invalid signature')
    return pickle.loads(pickled)`,
      explanation: 'Never use pickle.loads() with untrusted data - it can execute arbitrary code. Use JSON for data serialization. If YAML is required, use safe_load(). If pickle is unavoidable, implement HMAC signing and only accept signed data from trusted sources.',
      references: [
        'https://docs.python.org/3/library/pickle.html#module-pickle',
        'https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data'
      ]
    },
    {
      cwe_id: 'CWE-502',
      language: 'javascript',
      insecure_example: `// INSECURE: eval for deserialization
const obj = eval('(' + userInput + ')');

// INSECURE: node-serialize with untrusted data
const serialize = require('node-serialize');
const obj = serialize.unserialize(userInput);`,
      secure_example: `// SECURE: Use JSON.parse
const obj = JSON.parse(userInput);

// SECURE: Validate structure after parsing
const schema = {
  type: 'object',
  properties: {
    name: { type: 'string' },
    age: { type: 'number' }
  },
  required: ['name']
};

const Ajv = require('ajv');
const ajv = new Ajv();
const validate = ajv.compile(schema);

const obj = JSON.parse(userInput);
if (!validate(obj)) {
  throw new Error('Invalid data structure');
}`,
      explanation: 'Use JSON.parse() for deserialization - it cannot execute code. Always validate the structure with JSON Schema (ajv). Never use eval() or node-serialize with untrusted data.',
      references: [
        'https://www.npmjs.com/package/ajv'
      ]
    },

    // ========== CWE-918: SSRF ==========
    {
      cwe_id: 'CWE-918',
      language: 'javascript',
      insecure_example: `// INSECURE: Unvalidated URL from user
const response = await fetch(userProvidedUrl);

// INSECURE: Axios with user input
const data = await axios.get(req.query.url);`,
      secure_example: `// SECURE: URL allowlist validation
const ALLOWED_HOSTS = ['api.example.com', 'cdn.example.com'];

function isUrlSafe(urlString) {
  try {
    const url = new URL(urlString);
    
    // Check allowlist
    if (!ALLOWED_HOSTS.includes(url.hostname)) {
      return false;
    }
    
    // Block private IPs
    const ip = url.hostname;
    if (ip.match(/^(10|127|172\\.(1[6-9]|2[0-9]|3[01])|192\\.168)\\./)) {
      return false;
    }
    
    // Block cloud metadata
    if (ip === '169.254.169.254') {
      return false;
    }
    
    return true;
  } catch {
    return false;
  }
}

if (isUrlSafe(userUrl)) {
  const response = await fetch(userUrl);
}`,
      explanation: 'Always validate URLs against an allowlist of permitted hosts. Block private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.1) and cloud metadata endpoints (169.254.169.254). Use DNS rebinding protection.',
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html'
      ]
    },
    {
      cwe_id: 'CWE-918',
      language: 'python',
      insecure_example: `# INSECURE: Unvalidated URL
import requests
response = requests.get(user_url)

# INSECURE: urllib with user input
from urllib.request import urlopen
data = urlopen(user_provided_url).read()`,
      secure_example: `# SECURE: URL validation with allowlist
import requests
from urllib.parse import urlparse
import ipaddress

ALLOWED_HOSTS = ['api.example.com', 'cdn.example.com']
BLOCKED_IPS = ['127.0.0.1', '169.254.169.254']

def is_url_safe(url_string):
    try:
        parsed = urlparse(url_string)
        
        # Check allowlist
        if parsed.hostname not in ALLOWED_HOSTS:
            return False
        
        # Block private networks
        try:
            ip = ipaddress.ip_address(parsed.hostname)
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                return False
        except ValueError:
            pass  # Not an IP, hostname validation passed
        
        return parsed.scheme in ['http', 'https']
    except Exception:
        return False

if is_url_safe(user_url):
    response = requests.get(user_url, timeout=5)`,
      explanation: 'Validate URLs against allowlists. Use Python ipaddress module to detect private networks (is_private, is_loopback). Block cloud metadata (169.254.169.254). Set timeouts to prevent hang attacks.',
      references: [
        'https://docs.python.org/3/library/ipaddress.html'
      ]
    },

    // ========== CWE-798: Hardcoded Credentials ==========
    {
      cwe_id: 'CWE-798',
      language: 'any',
      insecure_example: `// INSECURE: Hardcoded API key
const API_KEY = 'sk_live_abc123xyz789';
const SECRET_TOKEN = 'ghp_1234567890abcdefghijklmnopqrstuvwxyz';

# INSECURE: Hardcoded password
password = "MySecretP@ssw0rd"
db_connection = f"postgresql://user:{password}@localhost/db"`,
      secure_example: `// SECURE: Use environment variables
const API_KEY = process.env.API_KEY;
const SECRET_TOKEN = process.env.GITHUB_TOKEN;

# SECURE: Environment variables (Python)
import os
password = os.environ.get('DB_PASSWORD')
api_key = os.getenv('API_KEY')

# SECURE: Secret management (AWS)
import boto3
client = boto3.client('secretsmanager')
secret = client.get_secret_value(SecretId='prod/api/key')

# SECURE: Azure Key Vault
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

credential = DefaultAzureCredential()
client = SecretClient(vault_url="https://myvault.vault.azure.net", credential=credential)
secret = client.get_secret("api-key")`,
      explanation: 'Never hardcode secrets in source code. Use environment variables for local development. In production, use secret management systems: AWS Secrets Manager, Azure Key Vault, HashiCorp Vault, or Kubernetes Secrets. Implement secret rotation policies. Use .gitignore to prevent .env files from being committed.',
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html'
      ]
    }
  ];
}
