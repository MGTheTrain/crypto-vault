---
status: accepted
date: 2024-12-26
decision-makers: [Tech Lead, Backend Team]
consulted: [DevOps Team, Frontend Team]
informed: [Product Team, QA Team]
---

# ADR-003: API-First Development with OpenAPI Specification

## Context and Problem Statement

We maintain API documentation in multiple disconnected formats:

1. **Swagger annotations** scattered in Go handler code (`@Summary`, `@Param`)
2. **Markdown tables** in README files (quickly outdated)
3. **Proto files** for gRPC endpoints
4. **Manual cURL commands** for testing

How do we establish a single source of truth for API contracts that:

- Generates type-safe server/client code automatically?
- Keeps documentation in sync with implementation?
- Enables contract testing before implementation?
- Works consistently across REST and gRPC APIs?
- Reduces manual documentation maintenance?

Without a unified approach, we face:

- **Documentation drift** (README tables outdated within weeks)
- **Duplication** (same endpoint documented 3+ places)
- **Inconsistency** (REST uses different patterns than gRPC)
- **Manual testing burden** (developers craft cURL commands from memory)
- **Integration friction** (clients reverse-engineer API from code)

## Decision Drivers

- **Single Source of Truth**: One specification file drives everything
- **Code Generation**: Auto-generate types/stubs from spec (reduce boilerplate)
- **Design-First**: Review API contracts before writing code
- **Client SDK Generation**: TypeScript/Python clients generated automatically
- **Contract Testing**: Validate requests/responses against spec
- **Tooling Ecosystem**: Compatible with Swagger UI, Postman, Redoc
- **Team Familiarity**: OpenAPI widely known, mature tooling
- **Cloud Native**: Industry standard for REST APIs in microservices

## Considered Options

- **Option 1: OpenAPI 3.0 Specification with oapi-codegen** (YAML-first)
- **Option 2: Continue with swaggo/swag Annotations** (Code-first)
- **Option 3: GraphQL Schema Definition Language** (SDL-first)
- **Option 4: Protocol Buffers for All APIs** (Proto-first)

## Decision Outcome

Chosen option: **"OpenAPI 3.0 with oapi-codegen"**, because:

- Single YAML spec drives server types, client SDKs, and documentation
- oapi-codegen generates idiomatic Go code (better than generic OpenAPI generators)
- Swagger UI/Redoc provide interactive documentation automatically
- Design-first workflow: review API before implementation
- Industry standard for REST APIs (widespread tooling support)
- Complements existing gRPC/Proto approach (use both where appropriate)

### Consequences

- **Good**, because API contract reviewed and approved before implementation starts
- **Good**, because generated types prevent request/response schema drift
- **Good**, because Swagger UI/Redoc documentation auto-generated (no manual markdown)
- **Good**, because TypeScript/Python client SDKs generated from same spec (consistency)
- **Good**, because contract tests validate implementation against spec
- **Good**, because Postman collections generated automatically from spec
- **Good**, because team can learn OpenAPI incrementally (widely documented)
- **Neutral**, because requires YAML proficiency (but simpler than learning GraphQL)
- **Neutral**, because generated code must not be edited (clear separation of concerns)
- **Neutral**, because two specs (OpenAPI for REST, Proto for gRPC) acceptable industry practice
- **Bad**, because adds build-time code generation step (CI/CD complexity)
- **Bad**, because changing spec requires regenerating all stubs (coordination cost)
- **Bad**, because vendor lock-in to OpenAPI tooling ecosystem

### Confirmation

**Automated Validation:**

```bash
# CI checks OpenAPI spec validity
make openapi-validate

# CI verifies generated code is up-to-date
git diff --exit-code internal/api/rest/v1/stub/

# Contract tests validate implementation
prism mock api/openapi/v1/crypto-vault.yaml
```

**Manual Review:**

- PR checklist: "Does OpenAPI spec match implementation?"
- Code review: "Are generated types used (not hand-written DTOs)?"
- Quarterly audit: "Is Swagger UI documentation accurate?"

## Pros and Cons of the Options

### Option 1: OpenAPI 3.0 with oapi-codegen (CHOSEN)

**Spec Location:** `api/openapi/v1/crypto-vault.yaml`

**Workflow:**

```
1. Design API in YAML → 2. Generate types → 3. Implement handlers → 4. Contract test
```

- **Good**, because single YAML file is source of truth (no annotation drift)
- **Good**, because oapi-codegen generates idiomatic Go structs (better than generic tools)
- **Good**, because Swagger UI/Redoc auto-generated from spec
- **Good**, because TypeScript/Python client SDKs generated automatically
- **Good**, because design-first approach (API review before coding)
- **Good**, because Postman collections generated from spec
- **Good**, because contract testing with Prism mock server
- **Good**, because works with existing gRPC/Proto approach (complementary)
- **Neutral**, because requires YAML proficiency (learning curve)
- **Neutral**, because generated code must not be edited (discipline required)
- **Bad**, because CI/CD must run code generation step
- **Bad**, because changing spec requires coordinated regeneration

### Option 2: Continue with swaggo/swag Annotations

**Approach:** Annotate Go handlers with `@Summary`, `@Param` comments

```go
// @Summary Upload blob
// @Param file formData file true "File to upload"
func (h *BlobHandler) UploadBlob(c *gin.Context) { ... }
```

- **Good**, because annotations stay close to implementation (single file)
- **Good**, because no separate spec file to maintain
- **Good**, because existing team familiarity (already using swag)
- **Neutral**, because Swagger UI still generated
- **Bad**, because annotations pollute handler code (mixing concerns)
- **Bad**, because no design-first workflow (can't review API before coding)
- **Bad**, because clients must wait for implementation to get spec
- **Bad**, because harder to generate TypeScript/Python clients (less mature tooling)
- **Bad**, because refactoring handlers breaks documentation

### Option 3: GraphQL Schema Definition Language

**Approach:** Replace REST with GraphQL

```graphql
type Mutation {
  uploadBlob(file: Upload!, encryptionKeyId: ID): BlobMeta
}
```

- **Good**, because single schema defines all operations
- **Good**, because clients request only needed fields (efficient)
- **Good**, because introspection enables auto-generated docs
- **Neutral**, because strong typing system
- **Bad**, because major architectural change (REST → GraphQL)
- **Bad**, because team must learn GraphQL (steep learning curve)
- **Bad**, because existing REST clients break (migration burden)
- **Bad**, because file uploads in GraphQL more complex than REST multipart
- **Bad**, because gRPC still needed (two paradigms: GraphQL + gRPC)

### Option 4: Protocol Buffers for All APIs

**Approach:** Replace REST with gRPC everywhere

```protobuf
service BlobService {
  rpc UploadBlob(BlobUploadRequest) returns (BlobMetaResponse);
}
```

- **Good**, because single specification language (Proto)
- **Good**, because excellent code generation for many languages
- **Good**, because type-safe, versioned contracts
- **Good**, because gRPC performance benefits (binary protocol)
- **Neutral**, because already using Proto for some services
- **Bad**, because browser support requires gRPC-Web proxy (complexity)
- **Bad**, because removes REST entirely (breaking change for external clients)
- **Bad**, because file upload in gRPC more complex (streaming)
- **Bad**, because REST widely expected by external integrations

## More Information

**Tooling Stack:**

- **Spec Format**: OpenAPI 3.0 (YAML)
- **Generator**: oapi-codegen v2.2.0 (Go-native, idiomatic output)
- **Validation**: openapi-generator-cli (JSON Schema validation)
- **Documentation**: Swagger UI v5.31.0, Redoc
- **Contract Testing**: Prism mock server (future)

**File Organization:**

```
api/openapi/v1/
├── crypto-vault.yaml          # Single source of truth
└── oapi-codegen-config.yaml   # Generator configuration

internal/api/rest/v1/
├── stub/
│   └── generated_types.go     # Auto-generated (DO NOT EDIT)
├── blob_handler.go            # Use generated types
└── key_handler.go
```

**Team Agreement:**

- OpenAPI spec changes require architecture review (not implementation PRs)
- Generated code (`stub/`) excluded from code review (only review spec changes)
- CI enforces generated code is up-to-date (fails if `git diff` shows changes)

**Re-evaluation Criteria:**

- Re-visit if oapi-codegen project abandoned (switch to openapi-generator)
- Re-visit if team size >20 (consider dedicated API design team)
- Annual review: Is OpenAPI-first improving velocity or adding friction?
