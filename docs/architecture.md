# Architecture and demonstration

The browser calls the Express API. Express authenticates the principal, authorizes roles, validates inputs, and writes MySQL transactions. Evidence bytes are staged in a generated storage name, then hashed by `forensic-service/hash_file.py` in chunks. A failed registration rolls back MySQL and removes the staged file.

On Windows PowerShell, `backend`, `frontend`, and `forensic-service` are sibling directories. From `backend`, reach the Python service with `cd ..\forensic-service`.

## Demonstration script

1. Log in as a bootstrapped administrator and create an investigator, analyst, and custodian.
2. Create a clearly labelled demo case such as `DEC-DEMO-001`.
3. Upload a temporary text file as demo evidence and show the recorded SHA-256.
4. Transfer custody from the collecting custodian to another custodian; show both custody rows.
5. Verify integrity successfully.
6. For a controlled demo only, modify the temporary demo bytes, run verification again, and show a `FLAGGED` item plus an unresolved alert. Do not present this as real evidence.
7. Resolve the alert, complete analysis, and close the case. Attempting closure earlier must return `409`.
8. Open the admin audit view and show successful and rejected security-relevant actions.

The graph path returned by Neo4j represents an association in the investigation model, not proof of wrongdoing or attribution.
