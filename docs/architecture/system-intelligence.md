# System Intelligence Architecture & Topology

## Runtime vs Code Dependency Models
AEGIS explicitly separates:
1. **Runtime Topology Graph**:
   ```text
   Gateway (HTTP) ──► Order Service (HTTP) ──► PostgreSQL (DATABASE)
                           │
                           └──► Payment Service (HTTP) ──► Redis (CACHE)
   ```
2. **Code Import Dependency Graph**:
   ```text
   OrderController ──► OrderService ──► PaymentClient ──► BaseRepository
   ```
This distinction prevents conflating architectural boundaries with code modularity.

## API Endpoints
- `GET /api/v1/intelligence/dependency-graph`: Exposes runtime nodes and edges with protocol metadata.
- `GET /api/v1/intelligence/services/{service_name}/context`: Emits bounded machine-readable unified service context.
