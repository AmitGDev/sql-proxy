# SQL Proxy Service

A C++23 service that sits between users and a PostgreSQL database, analyzing SQL statements before execution, enforcing access policies, classifying sensitive data exposure, and producing structured audit records.

---

## Table of Contents

1. [Setup](#setup)
2. [Project Structure](#project-structure)
3. [Design Decisions](#design-decisions)
4. [SQL Analysis Approach](#sql-analysis-approach)
5. [Access Policy Rules](#access-policy-rules)
6. [User Management](#user-management)
7. [Data Classification](#data-classification)
8. [Audit Logging](#audit-logging)
9. [DDL and DML Execution Decision](#ddl-and-dml-execution-decision)
10. [Interaction Model](#interaction-model)
11. [Limitations](#limitations)

---

## Setup

### Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Visual Studio | 2026 | C++23 compiler and IDE |
| Docker Desktop | Any recent | Runs PostgreSQL 16 |
| vcpkg | Any recent | C++ package manager |

### 1. Start the Database

```bash
docker run --name sql-proxy-db \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=testdb \
  -p 5432:5432 \
  -d postgres:16
```

Single-line command for Windows environments:
```bash
docker run --name sql-proxy-db -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=testdb -p 5432:5432 -d postgres:16
```

### 2. Install vcpkg Dependencies

```bash
git clone https://github.com/microsoft/vcpkg.git C:\vcpkg
C:\vcpkg\bootstrap-vcpkg.bat
C:\vcpkg\vcpkg install libpqxx:x64-windows
C:\vcpkg\vcpkg install nlohmann-json:x64-windows
C:\vcpkg\vcpkg integrate install
```

### 3. Seed the Database

Connect to the container:

```bash
docker exec -it sql-proxy-db psql -U postgres -d testdb
```

Run the seed script (`sql/seed.sql`):

```sql
CREATE TABLE customers (
    id    SERIAL PRIMARY KEY,
    name  TEXT NOT NULL,
    email TEXT NOT NULL,
    phone TEXT
);

CREATE TABLE products (
    id    SERIAL PRIMARY KEY,
    name  TEXT NOT NULL,
    price NUMERIC(10,2)
);

CREATE TABLE orders (
    id          SERIAL PRIMARY KEY,
    customer_id INTEGER REFERENCES customers(id),
    created_at  TIMESTAMP DEFAULT NOW()
);

CREATE TABLE order_items (
    id         SERIAL PRIMARY KEY,
    order_id   INTEGER REFERENCES orders(id),
    product_id INTEGER REFERENCES products(id),
    quantity   INTEGER,
    unit_price NUMERIC(10,2)
);

INSERT INTO customers (name, email, phone) VALUES
    ('Alice Smith',  'alice@example.com',  '555-0101'),
    ('Bob Jones',    'bob@example.com',    '555-0102'),
    ('Carol White',  'carol@example.com',  NULL),
    ('David Brown',  'david@example.com',  '555-0104');

INSERT INTO products (name, price) VALUES
    ('Laptop',    999.99),
    ('Mouse',      29.99),
    ('Keyboard',   79.99),
    ('Monitor',   399.99),
    ('Headphones', 149.99);

INSERT INTO orders (customer_id) VALUES (1),(1),(2),(3),(4);

INSERT INTO order_items (order_id, product_id, quantity, unit_price) VALUES
    (1,1,1,999.99),(1,2,2,29.99),(2,5,1,149.99),
    (3,3,1,79.99),(3,4,2,399.99),(4,2,3,29.99),
    (5,1,1,999.99),(5,3,1,79.99);
```

### 4. Configure VS2026

In Project Properties:
- **C++ Language Standard** → ISO C++23
- vcpkg integration handles include and library paths automatically after `integrate install`

### 5. Place Config Files

Copy `config` folder next to the built `.exe` (e.g. `x64/Release/`).

### 6. Build and Run

Build in Release or Debug mode and run. The proxy executes a suite of test requests and writes `audit.jsonl` in the same directory as the executable.

---

## Project Structure

```
sql-proxy/
│
├── UserManager.hpp/.cpp     - User registry
├── SqlAnalyzer.hpp/.cpp     - SQL parsing (type, tables, columns)
├── PolicyEngine.hpp/.cpp    - Access policy evaluation
├── Classifier.hpp/.cpp      - PII classification
├── DbExecutor.hpp/.cpp      - PostgreSQL execution via libpqxx
├── AuditLogger.hpp/.cpp     - Append-only JSONL audit log
├── Utility.hpp/.cpp         - Utility functions
├── main.cpp                 - Test runner:
│
├── ConnectToDbTest.cpp      - Tests DB connectivity
├── SqlAnalyzerTest.cpp      - Tests UserManager → SqlAnalyzer
├── PolicyEngineTest.cpp     - Tests SqlAnalyzer → PolicyEngine
├── FullPipelineTest.cpp     - Tests Full Pipeline: UserManager → SqlAnalyzer → PII classification → policy decision
├── ExecuteTest.cpp          - Tests Execute: Full Pipeline → DB execute → Audit 
│
├── config/
│   ├── users.json           - User definitions and roles
│   ├── schema.json          - Schema definitions
│   ├── classifier.json      - Classify definitions and roles
│   └── policies.json        - Access control rules
│
├── sql/
│   └── seed.sql             - DDL + DML for demo schema
│
└── README.md
```

### Internal Dependencies

```
ExecuteTest.cpp
  ├── SqlAnalyzer.hpp
  ├── PolicyEngine.hpp
  │     └── SqlAnalyzer.hpp
  ├── UserManager.hpp
  ├── Classifier.hpp
  ├── DbExecutor.hpp
  └── AuditLogger.hpp
        ├── SqlAnalyzer.hpp
        └── Classifier.hpp
```

No circular dependencies. `SqlAnalyzer.h` is the only header shared across multiple components.

### External Dependencies

| Library | Installed via | Used by |
|---------|--------------|---------|
| libpqxx | vcpkg | DbExecutor - PostgreSQL C++ client |
| nlohmann/json | vcpkg | PolicyEngine, UserManager, Classifier - JSON config parsing |

---

**Package Manager Selection**

Five options were evaluated for C++ dependency management:

| Tool | Vendor | VS2026 Integration | Windows Support | Best For |
|------|--------|--------------------|-----------------|----------|
| **vcpkg** | Microsoft | Native, automatic via `integrate install` | First-class | VS2026 / Windows projects |
| Conan | JFrog | Manual CMake/props wiring | Good, more setup | Cross-platform, CMake-centric projects |
| NuGet | Microsoft | Native (built into VS) | First-class | .NET primarily; sparse C++ ecosystem |
| Hunter | Open source | CMake only | Good | CMake-centric, self-contained builds |
| CPM.cmake | Open source | CMake only | Good | Lightweight CMake dependency management |

**vcpkg** was chosen because this project targets VS2026 on Windows. `vcpkg integrate install` wires include paths and library linking directly into Visual Studio with zero manual configuration - no `CMakeLists.txt`, no `.props` file editing. Conan is the better choice for cross-platform CMake projects but requires additional wiring to work cleanly with VS2026 project files. NuGet is built into VS but its C++ package ecosystem is sparse - most C++ libraries simply are not published there. Hunter and CPM.cmake are CMake-only and do not apply without a `CMakeLists.txt`. For a Windows-first project using VS2026 directly, vcpkg is the path of least resistance.


**PostgreSQL Client Library Selection**

Five options were evaluated for the PostgreSQL client layer:

| Library | Type | C++ Style | Best For |
|---------|------|-----------|----------|
| **libpqxx** | C++ wrapper over libpq | Modern, RAII | General C++ PostgreSQL client |
| libpq | Official C API | Manual, verbose | Maximum control, lowest overhead |
| SOCI | DB abstraction layer | Stream-based | Multi-database portability |
| pq | Lightweight wrapper | Minimal | Small projects, minimal deps |
| ODB | Full ORM | Object-mapped | Complex domain models, object persistence |

**libpqxx** was chosen because it provides a stable, idiomatic C++ interface over the official libpq without the boilerplate of the raw C API. It offers RAII-based resource management, clean result handling, and straightforward transaction support. libpq would offer maximum control but at the cost of manual memory management and verbose error handling - unjustified here. SOCI adds multi-database portability that this project does not need. ODB is a full ORM, which is over-engineering for a proxy layer that executes raw SQL. libpqxx is the natural middle ground: real C++, no unnecessary abstraction, integrates cleanly with VS2026 and vcpkg.


**JSON Library Selection**

Four options were evaluated for configuration parsing:

| Library | Type | JSON Support | Integration | Best For |
|---------|------|-------------|-------------|----------|
| **nlohmann/json** | Single-header generalist | Native, full | Drop-in, no linking | Config files, general use |
| Boost.PropertyTree | Legacy key-value tree | Limited - bolted on, values forced to strings | Massive Boost dependency | Legacy projects |
| Boost.JSON | Modern high-performance parser | Native, full | Requires linking full Boost ecosystem | High-throughput parsing |
| Glaze | C++20/23 specialist | Native, full | Compile-time reflection, rigid boilerplate | Extreme performance, hot paths |

**nlohmann/json** was chosen because it is the correct tool for this use case - small config files read once at startup. It makes JSON feel like a native C++ container, integrates as a single header with no linking required, and works out of the box with VS2026 and vcpkg without the `LNK2019` binary-matching friction that Boost introduces. Boost.PropertyTree forces all values to strings, losing type information. Boost.JSON and Glaze offer performance advantages that are irrelevant when parsing is not in a hot path. Developer clarity and maintainability outweigh marginal parse speed for a startup-time configuration loader.

---

## Design Decisions

### Six Single-Responsibility Components

Each component does exactly one thing and has no knowledge of the others. This was a deliberate choice over a monolithic approach for three reasons:

1. **Testability** - `SqlAnalyzer` and `Classifier` can be tested with no database present. `PolicyEngine` can be tested with no users or DB. Each component is independently verifiable.
2. **Replaceability** - the regex-based `SqlAnalyzer` could be swapped for a proper AST parser without touching any other component.
3. **Clarity for evaluation** - the exercise values reasoning and design; a clean separation makes each decision visible and reviewable.

### Default-Deny

If no policy rule matches a (user, table, statement type) combination, the request is denied. This is the correct secure default - access is never accidentally granted because a rule was forgotten. Every permission must be explicitly stated.

### Configuration Over Code

Users and policies are loaded from JSON files at startup. The hardcoded fallbacks in `main.cpp` exist only to allow the test suite to run if the config files are missing - they would not exist in production.

### Classifier Runs Twice for SELECT

PII classification runs before execution (on parsed column names) and again after execution (on actual DB column names returned by libpqxx). Three reasons make the second pass necessary:

1. **Parser imperfection** - the regex strips simple `AS` aliases correctly, so those are not a problem. The limit is expressions: column names buried inside function calls, concatenations, or casts cannot be extracted. For example:
   ```sql
   SELECT COALESCE(c.email, c.phone) AS contact
   FROM customers c;
   ```
   The regex strips `AS contact` and is left with `COALESCE(c.email, c.phone)` - it cannot parse inside the function call, so `email` and `phone` are never extracted. The current classifier also misses this - it checks column labels only, so both passes see the unresolvable expression and neither detects the underlying PII. This illustrates both a parser limit and a classifier limit. The second pass is the correct architectural hook for a future value-aware classifier that inspects actual result data rather than column names. For straightforward projections the DB result column names are exact for the actual output schema, where the regex may have been wrong.
2. **`SELECT *` with incomplete schema** - `JOIN` targets are not expanded by the current implementation (known limitation). The second pass sees every column the DB actually returned.
3. **Schema drift** - even with a complete `schema.json`, the live DB may have columns not yet reflected in it (e.g. after an untracked `ALTER TABLE`). The post-execution pass catches PII that slipped through.

### Audit Records for Denied Requests

The audit log records every request, including denied ones and unknown users. This is intentional - a pattern of denied requests is itself meaningful information for a security review. An attacker probing access boundaries would leave a trail even if they never successfully execute a statement.

---

## SQL Analysis Approach

Analysis is performed by `SqlAnalyzer` using C++ standard library regular expressions (`<regex>`). No external SQL parser is used.

**SQL Parser Selection**

Four options were evaluated for SQL analysis:

| Library | Type | AST Quality | Integration | Best For |
|---------|------|-------------|-------------|----------|
| **`<regex>` (std)** | Regex-based, no AST | Best-effort, known gaps | Zero deps, header-only | Design exercises, simple proxies |
| libpg_query | PostgreSQL's own internal parser | Full, authoritative | Not in vcpkg, Windows support not first-class | Production PostgreSQL proxies |
| ANTLR4 + SQL grammar | Generated parser from grammar file | Full AST | vcpkg available, large generated codebase | Multi-dialect SQL parsing |
| ZetaSQL | Google's SQL parser (BigQuery) | Full, battle-tested | Massive dependency, Linux-first | Large-scale SQL analysis infrastructure |

**`<regex>`** was chosen because it is the correct tool for this use case - a design exercise that prioritises architecture clarity and honest tradeoffs over parser completeness. `libpg_query` is the right answer for a production PostgreSQL proxy, but it is absent from vcpkg and requires a manual build on Windows/VS2026. ANTLR4 is portable but introduces a large generated codebase - the PostgreSQL `.g4` grammar files alone exceed 10,000–15,000 lines (split across Lexer and Parser), and once ANTLR4 generates C++ output the compiler faces tens of thousands of lines of generated headers and source files. All of this for the sole purpose of extracting table and column names. ZetaSQL is a non-starter on Windows. Critically, the `SqlAnalyzer` interface is deliberately designed for replaceability - swapping in `libpg_query` would touch only `SqlAnalyzer.cpp`, leaving the entire pipeline unchanged. The regex approach is an honest, documented tradeoff, not an oversight.

### Statement Type Detection

The uppercased SQL string is checked for which keyword it starts with (`SELECT`, `INSERT`, `UPDATE`, `DELETE`, `CREATE`, `ALTER`, `DROP`). The first matching keyword determines the type.

### Table Extraction

**SELECT:** Two passes - one regex captures the `FROM` clause up to the next SQL keyword (using a lookahead), a second regex iterates all `JOIN` occurrences. Bare aliases (`FROM customers c`) are stripped by taking only the first word of each token.

**DML:** Targeted per-type regexes: `INSERT INTO (\w+)`, `UPDATE (\w+) SET`, `DELETE FROM (\w+)`.

**DDL:** A single regex handles `CREATE/ALTER/DROP TABLE` with an optional `IF [NOT] EXISTS` clause.

### Column Extraction

**SELECT:** Everything between `SELECT` and `FROM` is captured. A wildcard `*` sets `is_wildcard=true`. Otherwise, columns are split by comma, table prefixes stripped (`t.col` → `col`), and `AS` aliases removed.

**INSERT:** The column list in parentheses after the table name is captured and split.

**UPDATE:** The `SET` clause is captured up to `WHERE` or end of string. A second regex iterates left-hand sides of assignments (`col = value` → `col`).

### Assumptions and Limitations

See the [Limitations](#limitations) section for a full list. The most significant assumption is that SQL input is well-formed and uses standard spacing. Obfuscated or heavily aliased SQL may not parse correctly.

---

## Access Policy Rules

Policies are defined in `policies.json` and evaluated by `PolicyEngine`.

### Rule Structure

```json
{
  "user":           "alice",
  "table":          "customers",
  "statementTypes": ["SELECT"],
  "effect":         "ALLOW"
}
```

- `user`: specific username or `"*"` for any user
- `table`: specific table name or `"*"` for any table
- `statementTypes`: array of types this rule covers; empty array means all types
- `effect`: `"ALLOW"` or `"BLOCK"`

### Evaluation Rules

**Most specific match wins.** Specificity is scored 0–3:

| Match | Score |
|-------|-------|
| specific user + specific table | 3 |
| specific user + wildcard table | 2 |
| wildcard user + specific table | 1 |
| wildcard user + wildcard table | 0 |

**Among equally specific rules, BLOCK beats ALLOW.**

**If no rule matches, the request is DENIED** (default-deny).

**Every table** referenced in the statement must pass. One blocked table denies the entire request.

### Demo Policy Summary

| User | Table | Types | Effect |
|------|-------|-------|--------|
| alice | * | SELECT | ALLOW |
| alice | orders | INSERT, UPDATE, DELETE | ALLOW |
| alice | * | CREATE, ALTER, DROP | BLOCK |
| bob | products | SELECT | ALLOW |
| bob | orders | SELECT | ALLOW |
| bob | customers | ALL | BLOCK |
| admin | * | ALL | ALLOW |
| * | * | ALL | BLOCK ← default deny |

---

## User Management

Users are defined in `users.json`:

```json
{
  "users": [
    { "name": "alice", "role": "analyst"  },
    { "name": "bob",   "role": "readonly" },
    { "name": "admin", "role": "admin"    }
  ]
}
```

Every request is validated against this registry before any SQL analysis or policy evaluation occurs. An unknown user is denied immediately and audited - the statement is never analyzed or executed.

All names are stored and compared case-insensitively (normalised to uppercase). The `role` field is informational - it appears in audit records but does not affect policy evaluation, which operates on the username alone.

---

## Data Classification

Classification is performed by `Classifier` based on column names. It does not inspect data values. Despite the current rules being PII-focused, the `Classifier` is general-purpose - tags are arbitrary strings and the design is not PII-specific.

### Classification Rules

Rules are loaded at startup from `config/classifier.json`. Each rule maps a list of column name patterns to a tag string. Tags are arbitrary - any classification scheme can be expressed without touching any code. If `classifier.json` is missing, `LoadDefaults()` provides the built-in fallback rules below.

| Column Name Pattern | Tag |
|--------------------|-----|
| `email`, `email_address`, `emailaddress`, `user_email`, `contact_email` | `PII.Email` |
| `phone`, `phone_number`, `phonenumber`, `mobile`, `mobile_number`, `contact_phone` | `PII.Phone` |

The `classifier.json` format supports any tag vocabulary - PII categories, regulatory frameworks, sensitivity levels, or domain-specific labels. A single column can match multiple rules and accumulate multiple tags (deduplicated automatically):

```json
{ "rules": [
  { "patterns": ["EMAIL", "EMAIL_ADDRESS"],       "tag": "PII.Email"  },
  { "patterns": ["PHONE", "MOBILE"],              "tag": "PII.Phone"  },
  { "patterns": ["SSN", "SOCIAL_SECURITY"],       "tag": "PII.SSN"    },
  { "patterns": ["SALARY", "COMPENSATION"],       "tag": "FINANCIAL"  },
  { "patterns": ["DIAGNOSIS", "CONDITION"],       "tag": "HIPAA"      },
  { "patterns": ["EMAIL", "DOB", "NATIONAL_ID"],  "tag": "GDPR"       },
  { "patterns": ["CARD_NUMBER", "CVV"],           "tag": "PCI-DSS"    },
  { "patterns": ["NOTES", "COMMENTS"],            "tag": "RESTRICTED" }
] }
```

In this example, an `email` column would accumulate both `PII.Email` and `GDPR` tags. All matched tags appear in the audit record.

### Wildcard Expansion

When a `SELECT *` is detected, the classifier looks up the table's columns in its registered schema, loaded at startup from `config/schema.json`. If `schema.json` is missing, `LoadSchemaDefaults()` provides the built-in fallback. The classifier then checks all columns for the table, correctly identifying PII exposure even when columns are not explicitly named in the query.

### Classification Does Not Block

Classification tags are informational - they appear in the audit log and are displayed to the caller, but they do not themselves cause a denial. Access control is the responsibility of the policy engine. A user with an ALLOW policy can retrieve PII columns; the audit record captures that they did so and which tags were exposed. This is the correct separation: classification informs, policy enforces.

---

## Audit Logging

Every request produces exactly one audit record, written as a single JSON line to `audit.jsonl` (newline-delimited JSON / JSONL format).

### Why JSONL

- **Append-only** - no file locking, no rewriting, no corruption risk on crash
- **Self-contained lines** - each line is valid JSON; no need to parse the full file
- **Streamable** - easy to tail, grep, or pipe into log aggregators (Splunk, ELK, Datadog)

### Fields Logged and Why

| Field | Why it is meaningful |
|-------|---------------------|
| `timestamp` | When the request arrived - required for timeline reconstruction |
| `user` | Who made the request - accountability anchor |
| `role` | User's role at time of request - contextualises access pattern |
| `statement_type` | SELECT / INSERT / etc. - coarse risk indicator |
| `tables` | Which tables were targeted - defines blast radius |
| `columns` | Which columns were projected or affected - precision of exposure |
| `is_wildcard` | `SELECT *` is higher risk than explicit columns - compliance flag |
| `pii_tags` | PII classifications detected - direct compliance evidence |
| `allowed` | Was the request permitted - primary audit outcome |
| `deny_reason` | If denied, exactly why - policy traceability |
| `affected_rows` | Rows changed by DML - impact tracking |
| `raw_sql` | Full original statement - forensic completeness |

### Sample Record

```json
{
  "timestamp": "2026-03-05T11:02:01Z",
  "user": "alice",
  "role": "analyst",
  "statement_type": "SELECT",
  "tables": ["CUSTOMERS"],
  "columns": ["NAME", "EMAIL"],
  "is_wildcard": false,
  "pii_tags": ["PII.Email"],
  "allowed": true,
  "deny_reason": "",
  "affected_rows": 0,
  "raw_sql": "SELECT name, email FROM customers"
}
```

---

## DDL and DML Execution Decision

The spec states: *"DDL and DML statements must be analyzed and may be allowed or rejected. Please explain your decision in the README."*

**Decision: DDL and DML are executed if the policy allows them.**

The rationale: the exercise asks for a proxy that enforces policies - not one that silently discards half the SQL universe. Blocking all DDL/DML would make the policy engine meaningless for write operations. Instead, the demo policies are configured conservatively:

- `alice` can INSERT/UPDATE/DELETE on `orders` only - not on `customers` or other tables
- `alice` is explicitly blocked from all DDL (CREATE, ALTER, DROP)
- `bob` has read-only access - no DML or DDL
- `admin` has full access

This demonstrates that the policy engine correctly handles both allow and block cases for all statement types.

**Production caveat:** In a real system, DDL would typically require a separate approval workflow and would not be auto-executed by a proxy. This is documented as a known limitation.

---

## Interaction Model

The proxy is implemented as a **service-based interface** rather than a transparent TCP proxy. The spec explicitly supports this choice - it states *"it may be implemented as a transparent proxy or as a service-based interface"*, directly anticipating the tradeoff and accepting both approaches as valid. In practice, callers invoke `ProcessRequest(user, sql)` directly through the C++ API, and all proxy logic (analysis, policy, classification, execution, audit) runs inline before any SQL reaches the database. A transparent proxy would instead sit on port 5432 and intercept the PostgreSQL wire protocol (pgwire), allowing any client - psql, DBeaver, libpqxx - to be proxied without code changes on the caller side. This was considered and consciously rejected: implementing a pgwire-compliant TCP listener is a significant standalone engineering effort involving binary protocol parsing, SQL extraction from query messages, well-formed error response serialisation, and full connection lifecycle management. Projects like pgBouncer and pgpool-II exist precisely because this is non-trivial, and doing it correctly within a 1-2 day exercise would consume all available time while contributing nothing to the parts the spec actually evaluates. Critically, the core logic is identical either way - whether a request arrives over TCP or through a direct API call, it passes through the exact same `UserManager → SqlAnalyzer → Classifier → PolicyEngine → DbExecutor → AuditLogger` pipeline. The transport layer is orthogonal to the correctness of that logic, and the service-based interface lets it be evaluated clearly without protocol noise. Enforcement is also complete: no SQL reaches the database without passing through the full proxy pipeline, and in a production deployment direct database access would be firewalled, making the service the only entry point.

---

## Limitations

| Area | Limitation |
|------|-----------|
| SQL Parsing | Regex-based, not a full AST parser - subqueries, CTEs, UNION, and window functions are not parsed correctly |
| SQL Parsing | Column aliases in complex expressions may not resolve correctly |
| SQL Parsing | Schema/database prefixes (`schema.table`) are not split - treated as a single token |
| SQL Parsing | String literals containing SQL keywords (e.g. `WHERE note = 'call WHERE needed'`) may confuse the SET clause regex |
| SQL Parsing | `INSERT INTO table VALUES (...)` without an explicit column list returns no columns |
| Policy Engine | No schema-level policy field - the spec mentions schema-level policies; only table-level is implemented |
| Policy Engine | No row-level security - cannot restrict "alice can only see her own rows" |
| Classifier | Column-name heuristics only - cannot detect PII stored in generically named columns (e.g. SSNs in a `notes` field) |
| Classifier | SQL expressions hide source columns from both passes - `SELECT COALESCE(email, phone) AS contact` produces `pii_tags: []` in the audit record even though PII was accessed. The raw SQL in the audit log is the only forensic trace. A future value-aware classifier inspecting actual result data would be the correct fix |
| Classifier | Wildcard expansion for multi-table JOINs only checks the primary FROM table, not all joined tables |
| DbExecutor | New connection per query - no connection pooling |
| Execution | Allowed DDL executes against the live database - in production, DDL should require a separate approval workflow |
| AuditLogger | No log rotation or size limit - `audit.jsonl` grows unbounded |
| Interaction | No network interface - callers must use the C++ API directly; no TCP proxy or HTTP server |