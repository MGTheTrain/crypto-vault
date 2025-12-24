# Blob Storage Schema Design

## Decision:

1. **For general blobs:**  
   Blobs will be stored in Blob Storage using the schema `/ID/Name`, where:
   - **ID:** A unique identifier for the entity (e.g. user ID, product ID).
   - **Name:** The name of the specific file (e.g. profile_picture.png, invoice.pdf).

2. **For key blobs:**  
   Key blobs will be stored using the schema `/fullKeyName`, where:
   - **fullKeyName:** The complete name for the key blob, constructed as `/{keyPairId}/{keyId}-{keyType}`, where:
     - **keyPairId:** A unique identifier for the key pair (e.g. user ID or application ID).
     - **keyId:** A unique identifier for the specific key within the pair.
     - **keyType:** The type of the key (e.g. RSA, AES, etc.).

## Conclusion:

- The `/ID/Name` schema for general blobs ensures logical grouping, easy retrieval, and a scalable storage structure.
- The `/fullKeyName` schema for key blobs, defined as `/{keyPairId}/{keyId}-{keyType}`, ensures each key is uniquely identified while maintaining clarity and efficiency in the organization.
- Both schemas leverage Blob Storage's hierarchical structure for better performance and management, providing an effective method for organizing and accessing blobs.
