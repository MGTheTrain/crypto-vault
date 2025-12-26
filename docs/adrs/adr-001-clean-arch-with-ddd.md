---
status: accepted
date: 2024-12-25
decision-makers: [Architecture Team, Tech Lead]
consulted: [Backend Team, DevOps Team]
informed: [Product Team, QA Team]
---

# ADR-001: Adopt Clean Architecture with Domain-Driven Design

## Context and Problem Statement

The crypto vault system manages cryptographic operations (encryption, signing, key management) and blob storage across multiple interfaces (REST API, gRPC API, CLI). How do we structure the codebase to support this complexity while enabling:

- Independent testing of business logic without infrastructure dependencies?
- Easy swapping of infrastructure components (Azure → AWS, PostgreSQL → MongoDB)?
- Clear collaboration boundaries for multiple teams working simultaneously?
- Long-term maintainability as the system grows in features and complexity?

Without a well-defined architecture, we risk:

- Tight coupling between business logic and infrastructure (hard to test, hard to change)
- Duplication of domain logic across REST, gRPC and CLI interfaces
- Difficulty onboarding new team members due to unclear code organization
- Technical debt accumulation as layers blur and dependencies tangle

## Decision Drivers

- **Testability**: Business logic must be testable in isolation without databases or cloud services
- **Multiple Interfaces**: Support REST API, gRPC API and CLI without duplicating domain logic
- **Infrastructure Flexibility**: Ability to swap Azure for AWS or PostgreSQL for MySQL with minimal changes
- **Domain Complexity**: Cryptographic operations (AES/RSA/ECDSA), key pairs, signature verification require clear modeling
- **Team Collaboration**: Multiple teams working on different layers (API, business logic, infrastructure)
- **Long-term Maintainability**: Architecture must support growth over 5+ years
- **SOLID Principles**: Follow industry best practices (Dependency Inversion, Single Responsibility)

## Considered Options

- **Option 1: Clean Architecture + Domain-Driven Design (Layered Architecture)**
- **Option 2: Monolithic MVC Architecture**
- **Option 3: Hexagonal Architecture (Ports and Adapters)**
- **Option 4: Microservices Architecture**

## Decision Outcome

Chosen option: **"Clean Architecture + Domain-Driven Design"**, because:

- Best fits our complexity level (complex domain, multiple interfaces, but not distributed system)
- Provides clear separation of concerns through well-defined layers
- Supports multiple interfaces (REST, gRPC, CLI) sharing same business logic
- Enables independent testing without infrastructure dependencies
- Industry-proven pattern for similar systems (cryptographic vaults, secure storage)
- Aligns with team's existing knowledge of DDD concepts
- Scales well from 10k to 10M users without architectural changes

### Consequences

- **Good**, because business logic in `domain/` and `app/` layers can be unit tested without databases/cloud services
- **Good**, because infrastructure changes (Azure → AWS) only affect `infrastructure/connector/` layer
- **Good**, because REST API, gRPC API and CLI share identical business logic (no duplication)
- **Good**, because clear layer boundaries enable parallel team development with minimal conflicts
- **Good**, because DDD aggregate roots (BlobMeta, CryptoKeyMeta) accurately model cryptographic concepts
- **Good**, because SOLID principles (especially Dependency Inversion) prevent tight coupling
- **Bad**, because steeper learning curve for team members unfamiliar with Clean Architecture/DDD
- **Bad**, because more boilerplate code (interfaces, dependency injection) compared to simple MVC
- **Bad**, because initial setup takes 2-3 weeks longer than monolithic approach
- **Neutral**, because many small interfaces improve testability but increase file count
- **Neutral**, because more directories provide clearer structure but require navigation effort

### Confirmation

**Automated Validation:**

```bash
# Enforce layer dependencies with Go module boundaries
go mod graph | grep "internal/domain -> internal/infrastructure" && exit 1

# Architecture fitness function (ArchUnit equivalent in Go)
golangci-lint run --enable=depguard \
  --depguard-rules="domain_no_infra: {
    files: internal/domain/**,
    deny: [internal/infrastructure]
  }"
```

**Manual Review:**

- Code reviews enforce: domain interfaces never import infrastructure implementations
- PR checklist: "Does this change maintain layer separation (domain → app → api)?"
- Quarterly architecture review: Verify no circular dependencies between layers

**Test Coverage Confirmation:**

- `domain/` layer: 95%+ unit test coverage (no external dependencies)
- `app/` layer: 85%+ unit test coverage (mocked repositories/connectors)
- `infrastructure/` layer: 70%+ integration test coverage (real databases)

## Pros and Cons of the Options

### Option 1: Clean Architecture + Domain-Driven Design CHOSEN

**Description:**
Four-layer architecture with dependency inversion:

1. **Entities Layer** (`internal/domain`): Business entities + interfaces
2. **Use Cases Layer** (`internal/app`): Application-specific business rules
3. **Interface Adapters Layer** (`internal/api`): REST/gRPC handlers
4. **Frameworks & Drivers Layer** (`internal/infrastructure`): Database, cloud, crypto implementations

**Project Structure:**

```
internal/
├── domain/       # Entities + Interfaces (no dependencies)
├── app/          # Use cases (depends on domain interfaces)
├── api/          # Controllers (depends on app use cases)
└── infrastructure/ # Implementations (depends on domain interfaces)
```

- **Good**, because domain layer has zero external dependencies (pure business logic)
- **Good**, because supports multiple interfaces (REST, gRPC, CLI) naturally
- **Good**, because infrastructure is swappable (Azure → AWS without touching domain)
- **Good**, because DDD aggregate roots model complex cryptographic concepts clearly
- **Good**, because aligns with SOLID principles (Dependency Inversion)
- **Good**, because industry-proven pattern (used by auth0, vault, AWS KMS)
- **Neutral**, because requires understanding of DDD concepts (aggregates, bounded contexts)
- **Neutral**, because more files/directories but clearer organization
- **Bad**, because steeper learning curve (2-3 weeks onboarding for new developers)
- **Bad**, because more boilerplate (interfaces, dependency injection)

### Option 2: Monolithic MVC Architecture

**Description:**
Traditional Model-View-Controller with tight coupling:

```
internal/
├── models/       # Database models (GORM structs)
├── controllers/  # HTTP handlers (directly use models)
└── services/     # Business logic mixed with infrastructure
```

- **Good**, because simple to understand (traditional web app pattern)
- **Good**, because faster initial development (no interfaces, direct DB access)
- **Good**, because fewer files/directories
- **Neutral**, because works well for simple CRUD apps
- **Bad**, because business logic tightly coupled to infrastructure (hard to test)
- **Bad**, because difficult to add gRPC without duplicating logic
- **Bad**, because infrastructure changes (Azure → AWS) require touching business logic
- **Bad**, because doesn't scale well with domain complexity
- **Bad**, because violates SOLID principles (especially Dependency Inversion)

### Option 3: Hexagonal Architecture (Ports and Adapters)

**Description:**
Similar to Clean Architecture but emphasizes "ports" (interfaces) and "adapters" (implementations):

```
internal/
├── core/         # Business logic (hexagon center)
├── ports/        # Interfaces for external systems
└── adapters/     # Implementations (HTTP, DB, cloud)
```

- **Good**, because clear separation of core business logic from external systems
- **Good**, because highly testable (mock all ports)
- **Good**, because similar benefits to Clean Architecture
- **Neutral**, because conceptually similar to Clean Architecture (different naming)
- **Bad**, because "ports/adapters" terminology less familiar than "domain/infrastructure"
- **Bad**, because no explicit application/use case layer (business logic scattered)

### Option 4: Microservices Architecture

**Description:**
Split into separate services:

- Blob Service (upload/download)
- Key Service (key management)
- Crypto Service (encryption/signing)

* **Good**, because independent deployment of services
* **Good**, because language flexibility (Go for crypto, Python for ML features)
* **Neutral**, because suitable for large teams (50+ developers)
* **Bad**, because massive operational overhead (Kubernetes, service mesh, distributed tracing)
* **Bad**, because distributed transactions complexity (blob + signature linking)
* **Bad**, because network latency between services
* **Bad**, because overkill for current team size (5-10 developers)
* **Bad**, because testing complexity (need all services running)

## More Information

**Implementation Timeline:**

- **Week 1-2**: Refactor existing code into layered structure
- **Week 3**: Create domain interfaces for repositories/connectors
- **Week 4**: Implement dependency injection in `cmd/main.go`
- **Week 5**: Add architecture tests (ArchUnit/depguard)

**References:**

- [Clean Architecture by Robert C. Martin](https://blog.cleancoder.com/uncle-bob/2012/08/13/the-clean-architecture.html)
- [Domain-Driven Design by Eric Evans](https://www.domainlanguage.com/ddd/)
- [Hexagonal Architecture](https://alistair.cockburn.us/hexagonal-architecture/)

**Team Agreement:**

- All new features must follow layered structure
- Domain layer PRs require architecture team review
- Infrastructure changes do not require domain layer changes

**Re-evaluation Criteria:**

- Re-visit if team grows beyond 50 developers (consider microservices)
- Re-visit if adding 5+ new interfaces beyond REST/gRPC/CLI
- Quarterly review: Are layer boundaries still maintained?
