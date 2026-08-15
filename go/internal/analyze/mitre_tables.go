package analyze

// MITRE reference tables, generated from the Python analyzer so both builds
// map evidence to the same techniques.

// AtlasTechnique describes one MITRE ATLAS technique.
type AtlasTechnique struct {
	Name        string
	Tactic      string
	Description string
}

// AtlasTechniques is the ATLAS subset TRACE maps evidence to.
var AtlasTechniques = map[string]AtlasTechnique{
	"AML.T0010": {Name: "Prompt Injection", Tactic: "", Description: "Crafting adversarial prompts to manipulate AI model behavior, bypass safety controls, or extract sensitive information."},
	"AML.T0011": {Name: "LLM Jailbreak", Tactic: "", Description: "Techniques to bypass LLM safety guardrails and produce disallowed content or actions."},
	"AML.T0025": {Name: "Modify Model", Tactic: "", Description: "Tampering with or replacing model weights, configuration, or inference parameters to alter outputs."},
	"AML.T0043": {Name: "Craft Adversarial Input", Tactic: "", Description: "Creating specially crafted inputs designed to trigger unintended model behavior or reveal training data."},
	"AML.T0048": {Name: "AI Tool Integration", Tactic: "", Description: "Adversary leverages legitimate AI tool integrations (plugins, agents, APIs) as an attack vector."},
	"AML.T0049": {Name: "Exploit AI Tool Integration", Tactic: "", Description: "Exploiting vulnerabilities in AI tool integration points (tool calls, function dispatch, plugin systems)."},
	"AML.T0050": {Name: "LLM Data Exfiltration", Tactic: "", Description: "Extracting data from LLM conversations, system prompts, or context windows through various techniques."},
	"AML.T0052": {Name: "LLM Prompt Leak", Tactic: "", Description: "Techniques to extract system prompts, few-shot examples, or other privileged instructions from LLMs."},
	"AML.T0054": {Name: "AI-Generated Content", Tactic: "", Description: "Using AI-generated content for phishing, social engineering, disinformation, or malware generation."},
	"AML.T0055": {Name: "LLM Credential Theft", Tactic: "", Description: "Stealing API keys, tokens, or other credentials used to access AI services."},
}

// AttackTechniqueInfo is the name and tactic of a MITRE ATT&CK technique.
type AttackTechniqueInfo struct {
	Name   string
	Tactic string
}

// AttackTechniques is the AI/ML-relevant ATT&CK subset.
var AttackTechniques = map[string]AttackTechniqueInfo{
	"T1190": {Name: "Exploit Public-Facing Application", Tactic: "Initial Access"},
	"T1133": {Name: "External Remote Services", Tactic: "Initial Access"},
	"T1078": {Name: "Valid Accounts", Tactic: "Initial Access"},
	"T1059": {Name: "Command and Scripting Interpreter", Tactic: "Execution"},
	"T1203": {Name: "Exploitation for Client Execution", Tactic: "Execution"},
	"T1053": {Name: "Scheduled Task/Job", Tactic: "Execution"},
	"T1548": {Name: "Abuse Elevation Control Mechanism", Tactic: "Privilege Escalation"},
	"T1068": {Name: "Exploitation for Privilege Escalation", Tactic: "Privilege Escalation"},
	"T1087": {Name: "Account Discovery", Tactic: "Discovery"},
	"T1083": {Name: "File and Directory Discovery", Tactic: "Discovery"},
	"T1046": {Name: "Network Service Discovery", Tactic: "Discovery"},
	"T1005": {Name: "Data from Local System", Tactic: "Collection"},
	"T1039": {Name: "Data from Network Shared Drive", Tactic: "Collection"},
	"T1114": {Name: "Email Collection", Tactic: "Collection"},
	"T1041": {Name: "Exfiltration Over C2 Channel", Tactic: "Exfiltration"},
	"T1048": {Name: "Exfiltration Over Alternative Protocol", Tactic: "Exfiltration"},
	"T1567": {Name: "Exfiltration Over Web Service", Tactic: "Exfiltration"},
	"T1071": {Name: "Application Layer Protocol", Tactic: "Command and Control"},
	"T1573": {Name: "Encrypted Channel", Tactic: "Command and Control"},
	"T1105": {Name: "Ingress Tool Transfer", Tactic: "Command and Control"},
	"T1486": {Name: "Data Encrypted for Impact", Tactic: "Impact"},
	"T1565": {Name: "Data Manipulation", Tactic: "Impact"},
	"T1552": {Name: "Unsecured Credentials", Tactic: "Credential Access"},
	"T1119": {Name: "Automated Collection", Tactic: "Collection"},
	"T1189": {Name: "Drive-by Compromise", Tactic: "Initial Access"},
	"T1200": {Name: "Hardware Additions", Tactic: "Initial Access"},
	"T1592": {Name: "Gather Victim Host Information", Tactic: "Reconnaissance"},
	"T1595": {Name: "Active Scanning", Tactic: "Reconnaissance"},
	"T1590": {Name: "Gather Victim Network Information", Tactic: "Reconnaissance"},
}

// AtlasToAttack maps an ATLAS technique to the ATT&CK techniques it implies.
var AtlasToAttack = map[string][]string{
	"AML.T0010": {"T1190", "T1059"},
	"AML.T0011": {"T1190", "T1059"},
	"AML.T0025": {"T1565", "T1078"},
	"AML.T0043": {"T1203"},
	"AML.T0048": {"T1071", "T1105"},
	"AML.T0049": {"T1059", "T1548"},
	"AML.T0050": {"T1048", "T1567"},
	"AML.T0052": {"T1087", "T1083"},
	"AML.T0054": {"T1486"},
	"AML.T0055": {"T1552"},
}

// KillChainStages is the intrusion kill chain, in order.
var KillChainStages = []string{"Reconnaissance", "Weaponization", "Delivery", "Exploitation", "Installation", "Command & Control", "Actions on Objectives"}

// credentialIndicators are the per-signal weights for its risk category.
var credentialIndicators = map[string]int{
	"api_key_exposed":      10,
	"credential_in_config": 5,
	"credential_in_log":    8,
	"shared_credential":    5,
	"hardcoded_secret":     7,
	"token_leak":           10,
}

// exfiltrationIndicators are the per-signal weights for its risk category.
var exfiltrationIndicators = map[string]int{
	"base64_encode":       5,
	"pipe_to_network":     10,
	"curl_upload":         8,
	"scp_outbound":        7,
	"dns_exfil":           8,
	"env_dump":            6,
	"clipboard_access":    3,
	"sensitive_file_read": 5,
}

// jailbreakIndicators are the per-signal weights for its risk category.
var jailbreakIndicators = map[string]int{
	"jailbreak_prompt":      15,
	"prompt_injection":      10,
	"safety_bypass":         12,
	"roleplay_escape":       8,
	"encoding_attack":       7,
	"system_prompt_extract": 5,
}

// autonomyIndicators are the per-signal weights for its risk category.
var autonomyIndicators = map[string]int{
	"agent_autonomous_exec": 15,
	"tool_chain":            8,
	"file_write":            5,
	"code_execution":        10,
	"network_access":        7,
	"privilege_escalation":  10,
	"persistent_agent":      5,
}
