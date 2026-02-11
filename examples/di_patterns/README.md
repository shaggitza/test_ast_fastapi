# FastAPI Dependency Injection Patterns

This directory contains real-world examples of various FastAPI dependency injection patterns. Each example demonstrates a common pattern used in production applications and includes test diff files that modify dependencies to validate the endpoint detection tool.

## Directory Structure

```
di_patterns/
├── class_based/          # Class instances as dependencies
├── function_based/       # Simple functions as dependencies
├── nested_deps/          # Dependencies with sub-dependencies
├── security_deps/        # OAuth2, Bearer tokens, and security
├── db_session/          # Database session management
└── request_context/     # Request context extraction
```

## Pattern Examples

### 1. Class-Based Dependencies (`class_based/`)

**Pattern**: Using class instances as dependencies, useful for services with state or configuration.

**Key Features**:
- `DatabaseService` class for simulated database operations
- `CacheService` class for in-memory caching
- Type-annotated dependencies using `Annotated[Service, Depends(factory)]`

**Endpoints**:
- `GET /items` - Lists items using database service
- `GET /items/{item_id}` - Gets item with cache fallback
- `POST /items/{item_id}/invalidate` - Invalidates cache

**Test Diff**: `change_database_service.diff`
- Modifies the `DatabaseService.get_item()` method
- Adds validation and error handling
- Should flag both GET endpoints that use this service

**Expected Detection**: Changes to `DatabaseService.get_item()` should be detected as affecting:
- `GET /items/{item_id}` (direct usage)
- Potentially `GET /items` if the dependency graph includes the service

---

### 2. Function-Based Dependencies (`function_based/`)

**Pattern**: Simple functions as dependencies, ideal for extracting query params, headers, or utilities.

**Key Features**:
- `get_current_user()` - Extract user from authorization header
- `get_pagination()` - Extract and validate pagination parameters
- `verify_api_key()` - Validate API key from custom header
- Multiple dependencies combined in endpoints

**Endpoints**:
- `GET /users/me` - Get current user profile
- `GET /users` - List users with pagination and API key
- `POST /users/me/settings` - Update user settings

**Test Diff**: `change_auth.diff`
- Modifies the `get_current_user()` function
- Adds logging to authentication flow
- Should flag all endpoints that depend on `get_current_user()`

**Expected Detection**: Changes to `get_current_user()` should affect:
- `GET /users/me` (direct dependency)
- `GET /users` (direct dependency)
- `POST /users/me/settings` (direct dependency)

---

### 3. Nested Dependencies (`nested_deps/`)

**Pattern**: Dependencies that depend on other dependencies, creating a dependency tree.

**Key Features**:
- 4-level dependency hierarchy
- Level 1: `get_api_key()`, `get_tenant_id()`
- Level 2: `get_database_connection()`, `get_user_context()`
- Level 3: `get_user_repository()`, `get_permission_checker()`
- Level 4: `get_user_service()`

**Endpoints**:
- `GET /users` - Uses the complete 4-level dependency chain
- `GET /users/{user_id}` - Uses database and context (level 2)
- `POST /users` - Uses user service (level 4)

**Test Diff**: `change_base_dep.diff`
- Modifies the base dependency `get_api_key()` (level 1)
- Adds support for multiple API keys
- Adds authentication logging
- Should flag ALL endpoints due to transitive dependencies

**Expected Detection**: Changes to `get_api_key()` should affect:
- `GET /users` (via user service → repository → database connection → api_key)
- `GET /users/{user_id}` (via database connection → api_key)
- `POST /users` (via user service → repository → database connection → api_key)

This tests the tool's ability to track transitive dependencies across multiple levels.

---

### 4. Security Dependencies (`security_deps/`)

**Pattern**: OAuth2, Bearer tokens, and scope-based authorization.

**Key Features**:
- `OAuth2PasswordBearer` scheme
- `HTTPBearer` scheme
- Token decoding and validation
- Scope-based permissions using `require_scope()` factory
- Admin-only endpoints

**Endpoints**:
- `GET /users/me` - Basic OAuth2 authentication
- `GET /users/me/items` - Requires active user
- `POST /items` - Requires "write" scope
- `DELETE /users/{user_id}` - Requires admin scope
- `GET /protected` - Uses HTTP Bearer authentication

**Test Diff**: `change_token_decode.diff`
- Modifies the `decode_token()` function
- Adds support for multiple token types
- Adds token hash for audit logging
- Should flag all endpoints that use token-based auth

**Expected Detection**: Changes to `decode_token()` should affect:
- `GET /users/me` (via get_current_user → decode_token)
- `GET /users/me/items` (via get_current_active_user → get_current_user → decode_token)
- `POST /items` (via require_scope → get_current_user → decode_token)
- `DELETE /users/{user_id}` (via get_admin_user → get_current_user → decode_token)
- `GET /protected` (via get_current_user_bearer → decode_token)

---

### 5. Database Session Dependencies (`db_session/`)

**Pattern**: Database session lifecycle management with transactions.

**Key Features**:
- `Database` class for connection management
- `Session` class with transaction support
- `get_db_session()` - Generator with cleanup
- `get_transactional_session()` - Automatic commit/rollback
- Proper resource cleanup using `finally` blocks

**Endpoints**:
- `GET /users` - Read-only session
- `GET /users/{user_id}` - Read-only session
- `POST /users` - Transactional session
- `PUT /users/{user_id}` - Transactional session
- `DELETE /users/{user_id}` - Transactional session

**Test Diff**: `change_session.diff`
- Modifies the `Session` class
- Adds query counting
- Adds transaction state validation
- Adds query logging
- Should flag all endpoints that use database sessions

**Expected Detection**: Changes to `Session` class should affect:
- All endpoints (they all use either DBSession or TransactionalSession)

---

### 6. Request Context Dependencies (`request_context/`)

**Pattern**: Extracting and aggregating request context information.

**Key Features**:
- `get_request_id()` - Extract or generate request ID
- `get_user_agent()` - Extract user agent
- `get_client_ip()` - Extract client IP (proxy-aware)
- `get_session_token()` - Extract session from cookie
- `get_request_context()` - Composite dependency aggregating all context
- `validate_session()` - Session validation
- `log_request()` - Automatic request logging

**Endpoints**:
- `GET /info` - Returns request context
- `GET /tracked` - Endpoint with automatic logging
- `GET /profile` - Requires session validation
- `POST /action` - Combines session validation and logging

**Test Diff**: `change_ip_extraction.diff`
- Modifies the `get_client_ip()` function
- Adds support for multiple proxy headers (CloudFlare, etc.)
- Should flag endpoints that use IP extraction

**Expected Detection**: Changes to `get_client_ip()` should affect:
- `GET /info` (via get_request_context → get_client_ip)
- `GET /tracked` (via log_request → get_request_context → get_client_ip)
- `GET /profile` (via get_request_context → get_client_ip)
- `POST /action` (via log_request → get_request_context → get_client_ip)

---

## Testing with the Tool

Each example includes a diff file that can be used to test the endpoint detector:

```bash
# Test class-based dependencies
fastapi-endpoint-detector analyze \
  --app examples/di_patterns/class_based/main.py \
  --diff examples/di_patterns/class_based/change_database_service.diff

# Test function-based dependencies
fastapi-endpoint-detector analyze \
  --app examples/di_patterns/function_based/main.py \
  --diff examples/di_patterns/function_based/change_auth.diff

# Test nested dependencies (most complex)
fastapi-endpoint-detector analyze \
  --app examples/di_patterns/nested_deps/main.py \
  --diff examples/di_patterns/nested_deps/change_base_dep.diff

# Test security dependencies
fastapi-endpoint-detector analyze \
  --app examples/di_patterns/security_deps/main.py \
  --diff examples/di_patterns/security_deps/change_token_decode.diff

# Test database session dependencies
fastapi-endpoint-detector analyze \
  --app examples/di_patterns/db_session/main.py \
  --diff examples/di_patterns/db_session/change_session.diff

# Test request context dependencies
fastapi-endpoint-detector analyze \
  --app examples/di_patterns/request_context/main.py \
  --diff examples/di_patterns/request_context/change_ip_extraction.diff
```

## Why These Patterns Matter

These patterns represent real-world FastAPI applications:

1. **Class-Based**: Common in applications using service layers or repositories
2. **Function-Based**: Standard pattern for extracting request data
3. **Nested Dependencies**: Realistic enterprise applications with layered architecture
4. **Security**: Essential for any production API with authentication
5. **Database Sessions**: Standard pattern for database-backed applications
6. **Request Context**: Important for logging, monitoring, and debugging

Testing with these patterns ensures the endpoint detector works correctly with real-world codebases, not just simple examples.

## Validation Criteria

For each pattern, the tool should:

1. **Correctly identify all affected endpoints** - No false negatives
2. **Trace dependencies through the entire chain** - Handle nested dependencies
3. **Differentiate between direct and transitive dependencies** - Confidence levels
4. **Handle different dependency injection styles** - Classes, functions, generators
5. **Work with FastAPI's security utilities** - OAuth2, Bearer, etc.
6. **Understand composite dependencies** - Dependencies that combine others

## Integration with Tests

These examples are used in `tests/integration/test_di_patterns.py` to provide comprehensive coverage of dependency injection patterns in real-world scenarios.
