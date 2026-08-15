# Velociraptor Artifact YAML Format & Packaging — Comprehensive Research

## 1. Artifact YAML Structure (Complete Schema)

### Required Fields
- **`name`** (string, required) — Unique identifier. Only `[A-Za-z0-9_.]` allowed; each dot-separated segment must start with a letter. Convention: dot-separated hierarchy (e.g., `Windows.Applications.Chrome.History`).

### Top-Level Fields

| Field | Type | Description | Searchable |
|-------|------|-------------|------------|
| `name` | string | Unique identifier (required) | Yes |
| `aliases` | sequence | Alternative names for the same artifact | Yes |
| `type` | string | `CLIENT` (default), `CLIENT_EVENT`, `SERVER`, `SERVER_EVENT`, `INTERNAL`, `NOTEBOOK` | Filterable |
| `description` | string (markdown) | Human-readable purpose & usage. Supports CommonMark. Start with a lead sentence. | Yes |
| `author` | string | Author name/handle/email | No |
| `reference` | sequence | List of URLs or markdown links for further reading | No |
| `parameters` | sequence | User-definable parameters (see §7) | No |
| `sources` | sequence | VQL query definitions producing result tables (see §6) | No |
| `precondition` | SELECT query | Top-level OS/platform guard (evaluated before all sources) | — |
| `export` | string (VQL) | Shared VQL (LET statements) available to all sources and importing artifacts | — |
| `imports` | sequence | List of artifact names whose `export` sections to import | — |
| `reports` | sequence | Report templates (Go templates with VQL) for GUI rendering | — |
| `column_types` | sequence | Column display hints (e.g., `timestamp`, `tree`, `preview_upload`) | — |
| `resources` | object | Resource limits (timeout, max_rows, max_upload_bytes, ops_per_second) | — |
| `tools` | sequence | External binary tool definitions | — |

### Minimal Viable Artifact
```yaml
name: Custom.Artifact.Name
description: |
  One-sentence summary of what this artifact does.
  
  Additional details here.

sources:
  - query: |
      SELECT * FROM info()
      LIMIT 10
```

---

## 2. Multi-OS Artifacts (Platform Conditions)

### Two Approaches

#### A. Single Artifact with Source-Level Preconditions (RECOMMENDED for related data)

```yaml
name: Custom.AIToolEvidence

sources:
  - name: WindowsData
    precondition: SELECT OS FROM info() WHERE OS = 'windows'
    query: |
      SELECT * FROM glob(globs='C:\\Users\\*\\AppData\\...')

  - name: LinuxData
    precondition: SELECT OS FROM info() WHERE OS = 'linux'
    query: |
      SELECT * FROM glob(globs='/home/*/.config/...')

  - name: MacOSData
    precondition: SELECT OS FROM info() WHERE OS = 'darwin'
    query: |
      SELECT * FROM glob(globs='/Users/*/Library/Application Support/...')
```

**Critical: Source-level preconditions trigger PARALLEL execution mode — each source gets its own scope. Variables from one source are NOT visible to others.**

#### B. Separate Per-OS Artifacts with a Common Alias

```yaml
# In each OS-specific artifact:
name: Windows.Applications.Chrome.History
precondition: SELECT OS From info() where OS = 'windows'
...

# Then create a unified alias in a Generic artifact:
name: Generic.Detection.Yara.Glob
aliases:
  - Windows.Detection.Yara.Glob
  - Linux.Detection.Yara.Glob
  - MacOS.Detection.Yara.Glob
```

### Common OS Preconditions
```yaml
# Windows only
precondition: SELECT OS FROM info() WHERE OS = 'windows'

# Linux only
precondition: SELECT OS FROM info() WHERE OS = 'linux'

# macOS only
precondition: SELECT OS FROM info() WHERE OS = 'darwin'

# Linux + macOS (not arm64)
precondition: SELECT OS FROM info() WHERE OS =~ 'linux|darwin' AND NOT Architecture = 'arm64'

# All platforms (no precondition needed, or)
precondition: SELECT TRUE FROM scope()

# Admin privilege check (any OS)
precondition: SELECT * FROM info() WHERE IsAdmin
```

### Cross-Platform Path Handling
Use `pathspec()` for Windows drive letters and `glob()` with OS-conditional globs:

```vql
-- Windows paths with drive letter
LET RootPath <= pathspec(Path=Root, accessor=Accessor)

-- Use accessor 'auto' for cross-platform (auto-selects OS/file/ntfs)
FROM glob(globs=PathGlob, accessor=Accessor)

-- Parse user from path (cross-platform pattern)
parse_string_with_regex(regex="/Users/(?P<User>[^/]+)", string=OSPath).User
-- or on Windows:
parse_string_with_regex(regex="\\\\Users\\\\(?P<User>[^\\\\]+)", string=OSPath).User
```

### Real-World Multi-OS Example: `Generic.Client.Info`
This built-in artifact uses **source-level preconditions** for OS-specific data:
- Source `LinuxInfo` with `precondition: SELECT OS From info() where OS = 'linux'`
- Source `WindowsInfo` with `precondition: SELECT OS From info() where OS = 'windows'`
- Source `BasicInformation` (no precondition — runs everywhere)
- Source `Users` (Windows-only precondition)

---

## 3. Artifact Packaging & Distribution

### How Artifacts Are Stored
- Built-in artifacts are compiled into the Velociraptor binary
- Custom artifacts are stored as YAML in `<datastore>/artifact_definitions/`
- Directory structure mirrors the dot-separated name hierarchy:
  ```
  artifact_definitions/
  └── Custom/
      ├── Artifact/
      │   └── Name.yaml
      └── Windows/
          └── LastUser.yaml
  ```

### Distribution Methods

1. **GUI Import** — Server → Artifact → Import (paste YAML or upload ZIP)
2. **CLI `--definitions` flag** — Accepts a directory or ZIP file:
   ```bash
   velociraptor --definitions /path/to/artifacts/ gui
   velociraptor --definitions artifacts.zip gui
   ```
3. **Config-based loading**:
   - `autoexec.artifact_definitions` — Inline YAML in config
   - `Frontend.artifact_definitions_directory` — Single directory
   - `defaults.artifact_definitions_directories` — List of directories
4. **VQL `artifact_set()` function** — Create artifacts programmatically
5. **Artifact Exchange** — Community repository at https://exchange.velocidex.com

### Packaging a Custom Artifact for Distribution
1. Save as `.yaml` file following naming convention
2. Optionally bundle multiple artifacts into a ZIP
3. Import via GUI or CLI `--definitions` flag
4. Custom artifacts appear with a ★ icon in the GUI

### Built-in vs Custom vs Compiled-in
- **Compiled-in**: In the binary, cannot be edited
- **Built-in** (from config/directories): Cannot be edited during runtime, require server restart
- **Custom** (in datastore): Editable at runtime via GUI or VQL

---

## 4. Best Practices for Forensic Collection Artifacts

### File Collection with Glob Patterns

```yaml
# Example from Generic.Collectors.File
parameters:
  - name: collectionSpec
    type: csv
    default: |
      Glob
      Users\*\NTUser.dat

sources:
  - query: |
      LET RootPath <= pathspec(Path=Root, accessor=Accessor)
      LET specs = SELECT RootPath + Glob AS Glob
        FROM collectionSpec
      LET hits = SELECT OSPath AS SourceFile, Size,
                        Mtime AS Modified, Ctime AS Changed,
                        Btime AS Created, Atime AS LastAccessed
        FROM glob(globs=specs.Glob, accessor=Accessor)
        WHERE NOT IsDir
         AND (Size <= MaxFileSize OR (log(message="Skipping...") AND FALSE))
      
      SELECT *, upload(file=SourceFile, accessor=Accessor, mtime=Modified) AS Upload
      FROM hits
```

**Key glob patterns:**
- Windows: `C:\Users\*\AppData\**\*.log` or `C:/Users/*/AppData/**/*.log`
- Linux: `/home/*/.config/**/*` 
- macOS: `/Users/*/Library/Application Support/**/*`
- Use `**` for recursive, `*` for single-level
- Use `{a,b,c}` for alternatives: `/path/*.{log,db,json}`

### Registry Collection (Windows)

```vql
-- Read a registry value
SELECT Data FROM reg_read(path='HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run')

-- Glob registry keys
SELECT FullPath, Data, Mtime FROM glob(globs='HKEY_LOCAL_MACHINE\\SOFTWARE\\**', accessor='registry')

-- Parse specific values
SELECT Key, Data FROM reg_key(path='HKEY_LOCAL_MACHINE\\SOFTWARE\\MyApp')
```

### SQLite Database Collection & Parsing

```vql
-- Standard pattern (from Windows.Applications.Chrome.History)
LET history_files = SELECT * FROM foreach(
  row={
     SELECT Uid, Name AS User, expand(path=Directory) AS HomeDirectory
     FROM Artifact.Windows.Sys.Users()
     WHERE Name =~ userRegex
  },
  query={
     SELECT User, OSPath, Mtime
     FROM glob(globs=historyGlobs, root=HomeDirectory)
  })

SELECT * FROM foreach(row=history_files,
  query={
    SELECT User, url AS visited_url, title, visit_count
    FROM sqlite(file=OSPath, query=urlSQLQuery)
  })
```

**Key VQL function**: `sqlite(file=<path>, query=<SQL>)` — queries a SQLite database on the endpoint without uploading it.

### JSON Log Parsing

```vql
-- Parse JSON lines (one JSON object per line)
SELECT timestamp(epoch=atoi(string=timestamp_str)) AS Timestamp,
       message AS Message,
       level AS Level
FROM parse_json(filename=OSPath, accessor='file')

-- Or for newline-delimited JSON:
SELECT * FROM parse_lines(filename=OSPath)
WHERE line =~ '^{'
LET parsed <= parse_json(data=line)

-- For structured JSON files:
SELECT * FROM parse_json(filename=OSPath)
```

### Process Listing with Filtering

```vql
-- Pattern from Linux.Network.NetstatEnriched
SELECT Pid, Name, Exe, CommandLine, Username
FROM pslist()
WHERE Name =~ ProcessNameRegex
  AND Exe =~ ProcessPathRegex
  AND CommandLine =~ CommandLineRegex
  AND Username =~ UsernameRegex
```

### Network Connection Collection

```vql
-- Pattern from Linux.Network.NetstatEnriched
SELECT Laddr.IP AS Laddr, Laddr.Port AS Lport,
       Raddr.IP AS Raddr, Raddr.Port AS Rport,
       Pid, Status,
       process_tracker_get(id=Pid).Data AS ProcInfo,
       join(array=process_tracker_callchain(id=Pid).Data.Name, sep=" -> ") AS CallChain
FROM connections()
WHERE Status =~ ConnectionStatusRegex
 AND Raddr =~ IPRegex
 AND ProcInfo.Name =~ ProcessNameRegex
```

---

## 5. VQL Patterns Reference

### Reading SQLite Databases
```vql
-- Basic query
SELECT * FROM sqlite(file='/path/to/db.sqlite', query='SELECT * FROM table_name')

-- With timestamp conversion (Chrome uses Windows filetime * 10)
SELECT timestamp(winfiletime=visit_time * 10) AS visit_time
FROM sqlite(file=OSPath, query=urlSQLQuery)

-- Parameterized SQL query
parameters:
  - name: urlSQLQuery
    default: |
      SELECT url, title, visit_count FROM urls
```

### Parsing JSON Logs Line by Line
```vql
-- Single JSON object per file
SELECT * FROM parse_json(filename=OSPath)

-- NDJSON (one JSON per line)
SELECT * FROM parse_lines(filename=OSPath)
WHERE line =~ '^{'
-- Then parse each line:
LET Parsed <= parse_json(data=line)
```

### Collecting File Metadata + Content
```vql
-- Metadata only (no upload)
SELECT OSPath, Size, Mtime, Ctime, Atime, Btime
FROM glob(globs=PathGlob)

-- Upload files with metadata
SELECT OSPath AS SourceFile, Size, Mtime AS Modified,
       upload(file=OSPath, accessor=Accessor) AS Upload
FROM glob(globs=PathGlob, accessor=Accessor)
WHERE NOT IsDir

-- Conditional upload with size limits
SELECT *, if(condition=Size < MaxFileSize,
        then=upload(file=OSPath),
        else=NULL) AS Upload
FROM glob(globs=PathGlob)
WHERE NOT IsDir
```

### Cross-Platform Path Handling
```vql
-- Build paths for different OSes
LET WindowsPaths = SELECT * FROM glob(globs='C:\\Users\\*\\AppData\\Roaming\\**\\config.json')
LET LinuxPaths = SELECT * FROM glob(globs='/home/*/.config/**/config.json')
LET MacOSPaths = SELECT * FROM glob(globs='/Users/*/Library/Application Support/**/config.json')

-- Use expand() to resolve user home directories
SELECT expand(path=Directory) AS HomeDirectory FROM Artifact.Windows.Sys.Users()

-- Parse username from path (Windows)
parse_string_with_regex(regex="\\\\Users\\\\(?P<User>[^\\\\]+)", string=OSPath).User

-- Parse username from path (macOS)
parse_string_with_regex(regex="/Users/(?P<User>[^/]+)", string=OSPath).User

-- Use pathspec for NTFS raw access
LET RootPath <= pathspec(Path=Root, accessor='ntfs')
```

---

## 6. Structuring Large Multi-Source Artifacts

### One Artifact vs Multiple

**Use ONE artifact when:**
- All sources collect related data for the same forensic purpose (e.g., all AI tool evidence)
- Sources share parameters and description
- You want a single collection to gather everything
- Results should appear in a unified report

**Use MULTIPLE artifacts when:**
- Sources are independently useful (e.g., process listing vs browser history)
- Different parameter sets are needed
- Different users would collect them at different times
- You want to minimize resource usage per collection

### Multi-Source Architecture (Serial vs Parallel)

**Serial mode** (no source-level preconditions) — sources share scope:
```yaml
sources:
  - name: Step1
    query: |
      LET X <= SELECT ...  -- X is visible to Step2
      SELECT * FROM ...
  - name: Step2
    query: |
      SELECT * FROM X     -- Can reference Step1's variables
```

**Parallel mode** (any source has precondition) — sources get independent scope:
```yaml
sources:
  - name: WindowsData
    precondition: SELECT OS FROM info() WHERE OS = 'windows'
    query: |
      LET X <= ...  -- X is NOT visible to MacOSData
      SELECT * FROM ...
  - name: MacOSData
    precondition: SELECT OS FROM info() WHERE OS = 'darwin'
    query: |
      -- Cannot reference X from WindowsData
      SELECT * FROM ...
```

### Using `export` for Shared VQL Across Sources
```yaml
export: |
  LET CommonGlob <= glob(globs=PathGlob, accessor='auto')
  LET CommonFilter <= ... 

sources:
  - name: Source1
    query: |
      SELECT * FROM CommonFilter WHERE ...
  - name: Source2
    query: |
      SELECT * FROM CommonFilter WHERE ...
```

The `export` section's VQL is prepended to every source. Other artifacts can import it via:
```yaml
imports:
  - Custom.AIToolEvidence
```

### Recommended Pattern for AI Tool Forensic Artifact

```yaml
name: Custom.AIToolEvidence
description: |
  Collects forensic evidence of AI tool usage across Windows, Linux, and macOS.
  
  Gathers configuration files, conversation logs, session data, and cache
  from AI coding assistants and chat tools.

type: CLIENT

export: |
  LET AIToolPaths <= SELECT * FROM glob(globs=SearchGlob, accessor='auto')
    WHERE NOT IsDir AND log(message="Found: " + OSPath)

parameters:
  - name: SearchGlob
    description: Glob pattern for AI tool files
    default: ...
  - name: UploadFiles
    type: bool
    default: Y
    description: Upload file content in addition to metadata

sources:
  - name: WindowsConfig
    precondition: SELECT OS FROM info() WHERE OS = 'windows'
    query: |
      ...

  - name: LinuxConfig
    precondition: SELECT OS FROM info() WHERE OS = 'linux'
    query: |
      ...

  - name: MacOSConfig
    precondition: SELECT OS FROM info() WHERE OS = 'darwin'
    query: |
      ...

  - name: ConversationLogs
    query: |
      SELECT OSPath, Size, Mtime, Modified,
             if(condition=UploadFiles,
                then=upload(file=OSPath)) AS Upload
      FROM AIToolPaths
      WHERE OSPath =~ 'conversation|history|chat|session'

column_types:
  - name: Mtime
    type: timestamp
  - name: Upload
    type: preview_upload
```

---

## 7. Artifact Parameters (Complete Reference)

### Parameter Schema
```yaml
parameters:
  - name: ParameterName          # Required - variable name in VQL
    friendly_name: Display Name  # Optional - shown in GUI
    description: Help text       # Optional - tooltip/description
    default: default_value       # Always a string, even for numbers
    type: string                 # Data type (see below)
    validating_regex: '^...$'   # Visual validation hint only
    choices:                     # For choices/multichoice types
      - OptionA
      - OptionB
```

### All Parameter Types

| Type | VQL Conversion | Description |
|------|----------------|-------------|
| `string` | None (passthrough) | Default type. Simple text input |
| `int` / `integer` / `int64` | `LET x <= int(int=x)` | Integer input |
| `float` | `LET x <= parse_float(string=x)` | Float input |
| `bool` | `LET x <= x =~ '^(Y\|TRUE\|YES\|OK)$'` | Checkbox |
| `timestamp` | `LET x <= timestamp(epoch=x)` | Date/time picker |
| `regex` | None (string) | Regex editor with suggestions |
| `regex_array` | `LET x <= parse_json_array(data=x)` | List of regex patterns |
| `yara` | None (string) | YARA rule editor with syntax highlighting |
| `json` | `LET x <= parse_json(data=x)` | JSON dict input |
| `json_array` | `LET x <= parse_json_array(data=x)` | JSON array input |
| `csv` | `LET x <= SELECT * FROM parse_csv(filename=x, accessor='data')` | Table-based CSV editor |
| `choices` | None (string) | Single-select dropdown |
| `multichoice` | `LET x <= parse_json_array(data=x)` | Multi-select checklist |
| `hidden` | None (string) | Not shown in GUI |
| `redacted` | None | Masked value display |
| `upload` | `LET x <= SELECT Content FROM http_client(url=x)` | File upload (<4MB) |
| `upload_file` | Written to temp file | File upload (any size, written to disk) |
| `server_metadata` | `LET x <= server_metadata().x` | Populated from server metadata |
| `artifactset` | `LET x <= SELECT * FROM parse_csv(...)` | Artifact name selector |
| `xml` | `LET x <= parse_xml(file=x, accessor="data")` | XML document input |
| `yaml` | `LET x <= parse_yaml(filename=x, accessor="data")` | YAML document input |
| `starlark` | `LET x <= starl(code=x)` | Starlark code block |

**Important**: Default values are ALWAYS strings. Use `"10"` not `10` for int defaults.

### Parameter Validation Pattern
```yaml
parameters:
  - name: MaxFiles
    type: int
    default: "100"
    validating_regex: '^\d{1,5}$'
```

In VQL, add extra validation:
```vql
LET MaxFiles <= if(condition=NOT MaxFiles =~ '^\d{1,5}$',
                   then=100,
                   else=int(int=MaxFiles))
```

---

## 8. Report Generation

### Reports Section
Artifacts can include a `reports` section that defines Go templates with embedded VQL for rendering results in the GUI.

```yaml
reports:
  - type: CLIENT
    template: |
      {{ define "pre" }}
      LET Cap(X) = upcase(string=X[0:1]) + X[1:]
      {{ end }}
      {{ $_ := Query "pre" | Expand }}

      # Results for {{ Scope "Hostname" }}
      {{ Query "SELECT * FROM source(source='BasicInformation')" | Table }}
```

### Report Template Features
- Go template syntax with VQL integration
- `{{ Query "..." | Table }}` — render query results as table
- `{{ Query "..." | TimeChart "column" }}` — render time chart
- `{{ Scope "varname" }}` — access scope variables
- `{{ if condition }} ... {{ end }}` — conditional rendering
- `{{ define "name" }} ... {{ end }}` — define reusable blocks
- `{{ range Query "..." | Expand }} ... {{ end }}` — iterate over results

### Column Types
Control how columns are displayed in the GUI:
```yaml
column_types:
  - name: Timestamp
    type: timestamp
  - name: Upload
    type: preview_upload
  - name: ChildrenTree
    type: tree
```

---

## Reference: Real Artifact Examples Studied

### 1. `Windows.Applications.Chrome.History` — SQLite + glob + user enumeration
- Uses `Artifact.Windows.Sys.Users()` to find user directories
- Globs for History files per user
- Queries SQLite with parameterized SQL
- Shows pattern: `glob → foreach → sqlite()`

### 2. `MacOS.Applications.Chrome.History` — macOS variant
- Uses `parse_string_with_regex()` to extract username from path
- Simpler glob pattern (no user enumeration needed)
- Direct `glob(globs=historyGlobs)` + `foreach → sqlite()`

### 3. `Generic.Client.Info` — Multi-OS with source-level preconditions + reports
- 5 sources with different preconditions (BasicInformation, LinuxInfo, WindowsInfo, Users)
- Includes `reports:` section with Go templates
- Shows `column_types` configuration
- Uses `export` for shared VQL

### 4. `Generic.Collectors.File` — CSV-parameterized file collection
- Uses `csv` type parameter for flexible glob patterns
- Multi-source (metadata + uploads) in serial mode
- Shows `pathspec()`, `upload()`, and `workers=` for parallel uploads

### 5. `Generic.Detection.Yara.Glob` — Cross-platform with aliases
- Uses `aliases` field for OS-specific names
- `upload` type parameter for YARA rules
- Conditional upload with `if(condition=UploadHits, then=upload_hits, else=hits)`
- Shows `column_types: preview_upload`

### 6. `Linux.Network.NetstatEnriched` — Filtering-heavy artifact
- 8 regex parameters for flexible filtering
- Uses `connections()` + `process_tracker_get()` + `process_tracker_callchain()`
- `column_types: tree` for process hierarchy

### Key VQL Plugins/Functions Reference

| Purpose | VQL Function/Plugin |
|---------|---------------------|
| File globbing | `glob(globs=..., accessor=...)` |
| SQLite query | `sqlite(file=..., query=...)` |
| JSON parsing | `parse_json(filename=...)` or `parse_json(data=...)` |
| Line-by-line parsing | `parse_lines(filename=...)` |
| File upload | `upload(file=..., accessor=...)` |
| Registry read | `reg_read(path=...)`, `reg_key(path=...)` |
| Process list | `pslist()` |
| Network connections | `connections()` |
| System info | `info()` |
| User enumeration | `Artifact.Windows.Sys.Users()` |
| Path building | `pathspec(Path=..., accessor=...)` |
| Path parsing | `parse_string_with_regex(regex=..., string=...)` |
| Conditional logic | `if(condition=..., then=..., else=...)` |
| Logging | `log(message=..., args=[...])` |
| Type checking | `typeof(a=variable)` |
| Process tracker | `process_tracker_get(id=...)`, `process_tracker_callchain(id=...)` |
| Timestamps | `timestamp(epoch=...)`, `timestamp(winfiletime=...)` |

### Accessor Types (for `glob()`, `upload()`, etc.)

| Accessor | Purpose |
|----------|---------|
| `auto` | Auto-selects appropriate accessor for OS |
| `file` | Regular filesystem |
| `ntfs` | Raw NTFS (bypasses file locks, can read alternate data streams) |
| `registry` | Windows registry |
| `data` | In-memory data (for parsing CSV/JSON parameters) |
| `scope` | Access query results as files |

---

## Summary of Key Design Decisions for AI Tool Evidence Artifact

1. **Use `type: CLIENT`** — this runs on endpoints
2. **Use source-level preconditions** for OS branching — gives clean per-OS result tables
3. **Use `export:` section** for shared VQL (common glob patterns, parsing functions)
4. **Use `parameters:` with sensible defaults** — regex type for filtering, csv type for file paths, bool for upload toggle
5. **Structure sources by data category** rather than by OS if results should be combined; by OS if each OS has very different data
6. **Use `column_types`** to ensure timestamps and uploads render correctly in GUI
7. **Include `precondition`** even on top-level if artifact is OS-specific
8. **Follow naming convention**: `Custom.AITools.{ToolName}.{DataType}`
9. **Add `aliases`** if creating per-OS variants that should appear under multiple search paths
10. **Test with `velociraptor gui`** on each target OS before deploying