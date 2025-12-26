---
status: accepted
date: 2024-12-25
decision-makers: [Infrastructure Team, Tech Lead]
consulted: [Backend Team, Security Team]
informed: [DevOps Team, Product Team]
---

# ADR-002: Blob Storage Path Schema Design

## Context and Problem Statement

We need to organize blobs in Azure Blob Storage (and future cloud providers) efficiently. The system stores:

1. **User data blobs** (documents, images) with optional signatures
2. **Cryptographic key blobs** (RSA/ECDSA/AES keys in PEM format)

How do we structure blob paths to support:

- Fast retrieval of individual blobs by ID?
- Efficient listing of all blobs for a specific user?
- Clear separation between data blobs and signature blobs?
- Linking signatures to original blobs without storing large binaries in the database?
- Scaling to millions of blobs per user?

Without a well-designed schema, we risk:

- Slow queries due to full container scans
- Name collisions when users upload files with identical names
- Difficulty implementing user-level access control
- Inability to efficiently list/delete all user data (GDPR compliance)

## Decision Drivers

- **Query Performance**: Fast retrieval by blob ID (< 100ms)
- **User Listing**: Efficiently list all blobs for a user (prefix query)
- **Scalability**: Support 10M+ blobs per user without performance degradation
- **Signature Linking**: Track which signature belongs to which original blob
- **Cloud Agnostic**: Schema must work with Azure Blob Storage, AWS S3, Google Cloud Storage
- **GDPR Compliance**: Ability to delete all user data efficiently
- **Name Collision Prevention**: Multiple users can upload "document.pdf" without conflicts
- **Key Pair Grouping**: Public/private keys stored together logically

## Considered Options

- **Option 1: Hierarchical Schema `/user_id/blob_id/filename` for blobs, `/key_pair_id/key_id-key_type.pem` for keys**
- **Option 2: Flat Schema `/blob_id` (no hierarchy)**
- **Option 3: Date-Based Schema `/user_id/YYYY/MM/DD/blob_id`**
- **Option 4: Signature Embedded in Database (not as separate blob)**

## Decision Outcome

Chosen option: **"Hierarchical Schema `/user_id/blob_id/filename`"**, because:

- Enables efficient user-level queries (`/user:alice/` prefix returns all Alice's blobs)
- Prevents name collisions (multiple users can have `document.pdf`)
- Scales to millions of blobs per user with O(log n) prefix search
- Works identically across Azure Blob Storage, AWS S3, Google Cloud Storage
- Signature blobs stored separately but linked via database foreign key
- Key pairs grouped logically under `key_pair_id` prefix

### Consequences

- **Good**, because prefix query `/user:alice/` lists all user blobs in O(log n) time
- **Good**, because `blob_id` prevents name collisions (two users with `document.pdf` get unique paths)
- **Good**, because signature linking via database provides audit trail (who signed, when)
- **Good**, because hierarchical structure scales to 10M+ blobs per user without degradation
- **Good**, because schema works across Azure, AWS S3, GCS (cloud-agnostic)
- **Good**, because GDPR compliance: delete `/user:alice/` deletes all user data in one operation
- **Good**, because key pairs grouped under `key_pair_id` (easy to list public/private pair)
- **Neutral**, because signature requires database lookup to find signature blob (acceptable tradeoff for flexibility)
- **Neutral**, because three-level hierarchy (`/user/blob/file`) slightly longer paths than flat schema
- **Bad**, because changing schema later requires bulk blob move operation (migration cost)
- **Bad**, because path length increases storage metadata overhead by ~50 bytes per blob

### Confirmation

**Automated Validation:**

```bash
# Validate blob paths follow schema in integration tests
func TestBlobPathSchema(t *testing.T) {
    path := connector.BuildBlobPath(userID, blobID, filename)
    assert.Regexp(t, `^/user:[^/]+/[0-9a-f-]{36}/[^/]+$`, path)
}

# Verify signature blob linking
func TestSignatureLinking(t *testing.T) {
    blob := repo.GetByID("blob-123")
    assert.NotNil(t, blob.SignatureBlobID)
    sigBlob := repo.GetByID(*blob.SignatureBlobID)
    assert.Contains(t, sigBlob.Name, ".sig")
}
```

**Performance Validation:**

```bash
# Benchmark user listing query
az storage blob list --account-name cryptovault \
  --container-name blobs \
  --prefix "user:alice/" \
  --query "length(@)" \
  --output tsv

# Expected: < 500ms for 1M blobs
```

**Manual Review:**

- Code review: All blob upload code uses `BuildBlobPath()` helper
- PR checklist: "Does new blob type follow hierarchical schema?"
- Quarterly audit: Scan storage for paths not matching regex pattern

## Pros and Cons of the Options

### Option 1: Hierarchical Schema `/user_id/blob_id/filename` (CHOSEN)

**Path Examples:**

```
/user:alice/6cd5a802-27b3-4272-a9c5-cc3451bc3568/document.pdf
/user:alice/f99cf0e6-80f3-4bc3-bfb2-db61d571d0dd/document.pdf.sig
/user:bob/7a8b9c0d-1e2f-3g4h-5i6j-7k8l9m0n1o2p/contract.docx
```

**Key Schema:**

```
/pair-abc123/d4915fae-8a11-4d3a-ad29-bbeb4db300d1-private.pem
/pair-abc123/7f2e9b3c-5d8a-4f1e-9c6b-8a3d5e7f9b2c-public.pem
```

- **Good**, because `user_id` prefix enables efficient listing (O(log n) on Azure/S3)
- **Good**, because `blob_id` prevents collisions (multiple "document.pdf" files)
- **Good**, because `filename` preserves user context (download shows original name)
- **Good**, because key pairs grouped under `key_pair_id` (easy to manage pairs)
- **Good**, because works identically on Azure, AWS S3, GCS (cloud-agnostic)
- **Good**, because GDPR-compliant: delete `/user:alice/` in one operation
- **Neutral**, because signature requires DB lookup (acceptable for traceability)
- **Neutral**, because 3-level hierarchy adds ~50 bytes metadata per blob
- **Bad**, because migration complexity if schema changes later
- **Bad**, because slightly longer paths than flat schema

### Option 2: Flat Schema `/blob_id`

**Path Examples:**

```
/6cd5a802-27b3-4272-a9c5-cc3451bc3568
/f99cf0e6-80f3-4bc3-bfb2-db61d571d0dd
```

- **Good**, because simplest possible schema (minimal path length)
- **Good**, because no directory structure overhead
- **Neutral**, because direct access by blob_id is fast
- **Bad**, because listing user blobs requires full container scan (O(n))
- **Bad**, because no logical grouping (all blobs in one flat namespace)
- **Bad**, because GDPR deletion requires querying database first then deleting each blob individually
- **Bad**, because filename lost (downloads show UUID instead of "document.pdf")
- **Bad**, because doesn't scale beyond 1M total blobs efficiently

### Option 3: Date-Based Schema `/user_id/YYYY/MM/DD/blob_id`

**Path Examples:**

```
/user:alice/2024/12/25/6cd5a802-27b3-4272-a9c5-cc3451bc3568
/user:bob/2024/12/24/f99cf0e6-80f3-4bc3-bfb2-db61d571d0dd
```

- **Good**, because natural partitioning by date (useful for lifecycle policies)
- **Good**, because efficient listing within date range
- **Neutral**, because user-level listing still works (`/user:alice/` prefix)
- **Bad**, because date filtering better handled by database index (redundant complexity)
- **Bad**, because 5-level hierarchy increases path length significantly
- **Bad**, because date-based partitioning not useful for crypto vault use case
- **Bad**, because users don't typically filter blobs by upload date

### Option 4: Signature Embedded in Database

**Approach:** Store signature bytes in `blob_metas.signature_data BYTEA` column

- **Good**, because no database lookup needed (signature in same row as blob metadata)
- **Good**, because atomic updates (blob + signature in one transaction)
- **Neutral**, because simplifies storage (one fewer blob to manage)
- **Bad**, because large signatures (256 bytes for RSA-2048) bloat database rows
- **Bad**, because database backup size increases significantly with many signed blobs
- **Bad**, because database not optimized for binary data (blob storage is)
- **Bad**, because can't leverage blob storage features (CDN, geo-replication)
- **Bad**, because ECDSA signatures (64 bytes) and RSA signatures (256 bytes) waste space in fixed-size columns

## More Information

**Implementation Example:**

```go
// infrastructure/connector/azure_blob_connector.go
func (c *AzureBlobConnector) BuildBlobPath(userID, blobID, filename string) string {
    return fmt.Sprintf("/%s/%s/%s", userID, blobID, filename)
}

func (c *AzureBlobConnector) BuildKeyPath(keyPairID, keyID, keyType string) string {
    return fmt.Sprintf("/%s/%s-%s.pem", keyPairID, keyID, keyType)
}
```

**Database Schema:**

```sql
CREATE TABLE blob_metas (
    id                  UUID PRIMARY KEY,
    user_id             VARCHAR(255) NOT NULL,
    name                VARCHAR(255) NOT NULL,
    signature_blob_id   UUID REFERENCES blob_metas(id),
    signature_file_name VARCHAR(255),
    INDEX idx_user_id (user_id),
    INDEX idx_signature_blob_id (signature_blob_id)
);
```

**Migration Plan:**

- **Phase 1** (Week 1): Implement schema for new uploads only
- **Phase 2** (Week 2-3): Background migration of existing blobs (if any)
- **Phase 3** (Week 4): Validation and cleanup

**Related Decisions:**

- ADR-001: Clean Architecture (blob path logic in `infrastructure/connector`, not `domain`)
- Future ADR: Blob Lifecycle Policies (date-based deletion based on DB metadata, not path)

**Team Agreement:**

- All blob storage operations use `BuildBlobPath()` helper (no hardcoded paths)
- Path schema changes require architecture team approval
- Integration tests must validate path format

**Re-evaluation Criteria:**

- Re-visit if migrating to object storage system without hierarchical namespace support
- Re-visit if blob count per user exceeds 100M (consider sharding)
- Annual review: Is prefix query performance still acceptable?
