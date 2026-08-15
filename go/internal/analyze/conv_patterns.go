package analyze

import "regexp"

// convPattern is one labelled conversation-forensics pattern.
type convPattern struct {
	Label string
	Re    *regexp.Regexp
}

// convCategory groups the patterns for one attack category, with the severity
// and recommendation TRACE attaches to a hit.
type convCategory struct {
	Name        string
	Description string
	Severity    string
	Patterns    []convPattern
}

// convCategories is the conversation-forensics catalog, mirroring the pattern
// tables in analyzer/conversation_parser.py.
var convCategories = []convCategory{
	{
		Name:        "system_prompt_extraction",
		Description: "Attempt to extract the system prompt",
		Severity:    "high",
		Patterns: []convPattern{
			{"reveal instructions", regexp.MustCompile(`(?i)(reveal|show|display|print|output|repeat|recite|write\s+out)\s+(your|the|my|system|initial|original|secret|hidden)\s*(instructions?|prompts?|directives?|rules?|guidelines?|constraints?)`)},
			{"what are your prompts", regexp.MustCompile(`(?i)what\s+(are|is)\s+(your|the|my)\s+(system|initial|original|secret|hidden|base)\s*(prompt|instruction|directive|rule)`)},
			{"ignore previous instructions", regexp.MustCompile(`(?i)ignore\s+(all\s+)?(previous|prior|above|earlier|past)\s*(instructions?|prompts?|directives?|rules?|constraints?)`)},
			{"system prompt extraction", regexp.MustCompile(`(?i)(system\s*prompt|initial\s*prompt|base\s*prompt|secret\s*prompt)\s*(extraction|leak|dump|read|reveal|output)`)},
			{"pretend/forget instructions", regexp.MustCompile(`(?i)(pretend|act\s+as|forget|disregard)\s+(your|the|all)\s*(previous|prior|above|normal|original)\s*(instructions?|rules?|constraints?)`)},
		},
	},
	{
		Name:        "jailbreak",
		Description: "Jailbreak / guardrail bypass attempt",
		Severity:    "critical",
		Patterns: []convPattern{
			{"DAN mode", regexp.MustCompile(`(?i)(do\s+anything\s+now|DAN\s*mode|you\s+are\s+now\s+DAN|enable\s+DAN|DAN\s+jailbreak|act\s+as\s+DAN|become\s+DAN)`)},
			{"roleplay bypass", regexp.MustCompile(`(?i)(you\s+are\s+now\s+(?:an?\s+)?unrestricted|you\s+have\s+no\s+(?:rules|restrictions|limitations|filters)|pretend\s+you\s+have\s+no\s+(?:rules|restrictions|filter)|bypass\s+(?:your|the|all)\s+(?:safety|filter|restrictions?|rules?))`)},
			{"encoding attack", regexp.MustCompile(`(?i)(base64\s*(decode|encode|encoded|decoded|string)|rot13|hex\s*(decode|encode)|decode\s+(?:this|the)\s+(?:base64|hex|rot13|encoded))`)},
			{"base64-obfuscated prompt", regexp.MustCompile(`(?i)(?:[A-Za-z0-9+/]{40,}={0,2})(?:\s*(?:decode|execute|run|interpret)\s)`)},
			{"developer mode", regexp.MustCompile(`(?i)(developer\s*mode|debug\s*mode|admin\s*mode|god\s*mode|root\s*mode|sudo\s*mode|override\s+(?:safety|security|filter|restrictions?|policy))`)},
			{"hypothetical bypass", regexp.MustCompile(`(?i)(in\s+a\s+hypothetical\s+(?:scenario|world|situation|universe)|hypothetically(?:\s+speaking)?,?\s*(?:what|how|if|could|would)|imagine\s+(?:a|an)\s+(?:world|scenario|situation)\s+where\s+there\s+are\s+no\s+(?:rules|restrictions|safety))`)},
		},
	},
	{
		Name:        "data_exfiltration",
		Description: "Request to read or exfiltrate sensitive data",
		Severity:    "critical",
		Patterns: []convPattern{
			{"read sensitive files", regexp.MustCompile(`(?i)(read|cat|type|display|show|print|dump|exfiltrate)\s+(?:the\s+)?(?:file|files?)\s*(?:at|from|in|containing)\s*(?:/etc/passwd|/etc/shadow|/etc/hosts|\.ssh|\.env|\.git|id_rsa|authorized_keys|credentials|secrets?|config)`)},
			{"direct sensitive path reference", regexp.MustCompile(`(?i)(?:/etc/passwd|/etc/shadow|/etc/hosts|\.ssh/id_rsa|\.ssh/authorized_keys|\.aws/credentials|\.env\b|\.git/config)`)},
			{"environment variable access", regexp.MustCompile(`(?i)(print|echo|show|display|output|list|dump|exfiltrate)\s*(?:the\s+)?(?:environment|env|ENV)\s*(?:variables?|vars?)`)},
			{"send data outbound", regexp.MustCompile(`(?i)(send|transmit|upload|post|curl|wget|fetch|http\s*(?:get|post|put)|webhook|exfil)\s*.*\s*(?:to|toward|at|via)\s*https?://`)},
			{"tool call: read sensitive path", regexp.MustCompile(`(?i)(?:read_file|cat|type)\s*[\(\"]?\s*(/etc/passwd|/etc/shadow|/etc/hosts|\.ssh/id_rsa|\.ssh/authorized_keys|\.env|\.git/config|\.aws/credentials|\.bashrc|\.zshrc|/root/)`)},
			{"tool call: environment variables", regexp.MustCompile(`(?i)(?:printenv|env|export|getenv|os\.environ|process\.env|Environment\.GetEnvironmentVariable)`)},
		},
	},
	{
		Name:        "privilege_escalation",
		Description: "Privilege escalation attempt",
		Severity:    "high",
		Patterns: []convPattern{
			{"execute as root/sudo", regexp.MustCompile(`(?i)(sudo\s+|run\s+as\s+root|execute\s+as\s+(?:root|admin|system)|escalate\s+privilege|privilege\s+escalation|become\s+root|switch\s+to\s+root)`)},
			{"disable safety", regexp.MustCompile(`(?i)(disable|turn\s+off|bypass|remove|deactivate|skip)\s*(?:the\s+)?(?:safety|security|guard|filter|restriction|content\s*policy|moderation|guardrail)`)},
			{"bypass restrictions", regexp.MustCompile(`(?i)(bypass|circumvent|evade|work\s+around|get\s+around|sidestep|subvert)\s*(?:the\s+)?(?:restrictions?|safeguards?|filters?|policies?|guards?|guardrails?|limits?|boundaries?)`)},
			{"unauthorized command execution", regexp.MustCompile(`(?i)(rm\s+-rf\s+/|format\s+[A-Z]:|del\s+/[sfq]|:(){ :\|:& };:|fork\s*bomb|chmod\s+777|chown\s+root)`)},
		},
	},
	{
		Name:        "credential_harvesting",
		Description: "Credential harvesting attempt",
		Severity:    "critical",
		Patterns: []convPattern{
			{"API key request", regexp.MustCompile(`(?i)(give\s+me|show|reveal|tell\s+me|what\s+is|what's\s+the|output|print)\s*(?:the\s+|your\s+|my\s+)?(?:api\s*key|api\s*token|access\s*key|access\s*token)`)},
			{"password request", regexp.MustCompile(`(?i)(give\s+me|show|reveal|tell\s+me|what\s+is|what's\s+the|output|print)\s*(?:the\s+|your\s+|my\s+)?(?:password|passwd|pass|secret)`)},
			{"token/secret extraction", regexp.MustCompile(`(?i)(extract|dump|exfiltrate|steal|harvest|collect)\s*(?:the\s+)?(?:tokens?|secrets?|credentials?|keys?|certificates?)`)},
			{"AWS/cloud credential access", regexp.MustCompile(`(?i)(aws_access_key|aws_secret_key|aws_session_token|AZURE_CLIENT_SECRET|GCP_SERVICE_ACCOUNT|service_account\.json|\.aws/credentials|export\s+(AWS_|AZURE_|GCP_|GOOGLE_))`)},
			{"private key extraction", regexp.MustCompile(`(?i)(-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY|ssh-rsa\s+AAAA|extract.*private\s+key|show.*private\s+key)`)},
		},
	},
	{
		Name:        "indirect_injection",
		Description: "Indirect prompt injection via external content",
		Severity:    "high",
		Patterns: []convPattern{
			{"multi-turn attack chain", regexp.MustCompile(`(?i)(now\s+that\s+you\s+have|since\s+we(?:'ve|\s+have)\s+established|building\s+on\s+(?:our|the|that)|continue\s+from\s+(?:where|the\s+previous)|as\s+(?:we\s+)?discussed(?:\s+earlier)?)`)},
			{"indirect injection via pasted content", regexp.MustCompile(`(?i)(ignore\s+(?:the\s+)?(?:above|previous|prior|earlier)\s*(?:text|content|instructions?|prompt)|the\s+(?:above|following|text|content)\s+(?:contains?|has|includes?)\s*(?:new|updated|real|actual)\s*(?:instructions?|rules?|directives?))`)},
			{"hidden instruction in data", regexp.MustCompile(`(?i)(system\s*:\s*|<system>|\\[system\\]|\\[INST\\]|\\[/INST\\]|<\s*!\s*--\s*ignore|<!--\s*(?:system|instruction|prompt|rule)\s*-->)`)},
		},
	},
}
