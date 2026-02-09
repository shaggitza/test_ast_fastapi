# Example FastAPI Project

This directory contains an example FastAPI application and sample diff files for testing the FastAPI Endpoint Change Detector.

## Directory Structure

```
examples/
├── README.md                      # This file
├── sample_fastapi_project/        # Complete example FastAPI application
│   ├── main.py                    # Application entry point
│   ├── routers/                   # API route handlers
│   │   ├── users.py               # User-related endpoints
│   │   └── items.py               # Item-related endpoints
│   ├── services/                  # Business logic layer
│   │   ├── user_service.py        # User service
│   │   └── item_service.py        # Item service
│   ├── models/                    # Pydantic data models
│   │   ├── user.py                # User models
│   │   └── item.py                # Item models
│   ├── database/                  # Database layer
│   │   └── connection.py          # Database connection
│   └── utils/                     # Utility functions
│       └── helpers.py             # Helper functions
└── diffs/                         # Sample diff files
    ├── simple_change.diff         # Single endpoint change
    ├── service_change.diff        # Service layer change
    ├── model_change.diff          # Model change (multi-endpoint impact)
    └── multi_file_change.diff     # Complex multi-file change
```

## Sample FastAPI Application

The example application is a simple API with users and items:

### Endpoints

| Method | Path | Description | Handler |
|--------|------|-------------|---------|
| GET | `/` | Health check | `main.py::root` |
| GET | `/api/users` | List all users | `routers/users.py::get_users` |
| GET | `/api/users/{id}` | Get user by ID | `routers/users.py::get_user` |
| POST | `/api/users` | Create new user | `routers/users.py::create_user` |
| PUT | `/api/users/{id}` | Update user | `routers/users.py::update_user` |
| DELETE | `/api/users/{id}` | Delete user | `routers/users.py::delete_user` |
| GET | `/api/items` | List all items | `routers/items.py::get_items` |
| GET | `/api/items/{id}` | Get item by ID | `routers/items.py::get_item` |
| POST | `/api/items` | Create new item | `routers/items.py::create_item` |

### Dependency Graph

```
main.py (FastAPI app)
├── routers/users.py
│   ├── services/user_service.py
│   │   ├── models/user.py
│   │   └── database/connection.py
│   └── models/user.py
├── routers/items.py
│   ├── services/item_service.py
│   │   ├── models/item.py
│   │   └── database/connection.py
│   └── models/item.py
└── utils/helpers.py (shared utility)
```

## Sample Diff Files

### simple_change.diff

A simple change to a single endpoint handler. Should only affect one endpoint.

**Changed file**: `routers/users.py`
**Expected affected endpoints**: `GET /api/users/{id}`

### service_change.diff

A change to the user service layer. Should affect multiple user endpoints.

**Changed file**: `services/user_service.py`
**Expected affected endpoints**:
- `GET /api/users`
- `GET /api/users/{id}`
- `POST /api/users`
- `PUT /api/users/{id}`
- `DELETE /api/users/{id}`

### model_change.diff

A change to the User model. Should affect all endpoints that use the model.

**Changed file**: `models/user.py`
**Expected affected endpoints**:
- All user endpoints (direct dependency)
- Potentially item endpoints (if they reference users)

### multi_file_change.diff

A complex change spanning multiple files. Tests transitive dependency detection.

**Changed files**:
- `database/connection.py`
- `utils/helpers.py`

**Expected affected endpoints**: All endpoints (shared dependencies)

## Running Examples

### Basic Usage

```bash
# From project root
fastapi-endpoint-detector \
    --app examples/sample_fastapi_project/main.py \
    --diff examples/diffs/simple_change.diff
```

### With JSON Output

```bash
fastapi-endpoint-detector \
    --app examples/sample_fastapi_project/main.py \
    --diff examples/diffs/service_change.diff \
    --format json
```

### Verbose with Dependency Tree

```bash
fastapi-endpoint-detector \
    --app examples/sample_fastapi_project/main.py \
    --diff examples/diffs/model_change.diff \
    --verbose \
    --show-tree
```

## Creating Your Own Diffs

To test with your own changes:

```bash
# Make changes to the sample project
# Then generate a diff
git diff > my_changes.diff

# Or create a diff between commits
git diff HEAD~1 HEAD > my_changes.diff

# Run the detector
fastapi-endpoint-detector \
    --app examples/sample_fastapi_project/main.py \
    --diff my_changes.diff
```

## Expected Output Examples

### simple_change.diff

```
FastAPI Endpoint Change Detector - Analysis Report
==================================================

Changes analyzed: 1 file, 1 function modified

Affected Endpoints:
  ✓ GET  /api/users/{id}     [HIGH confidence]
    └── Changed: routers/users.py::get_user (direct)

Unaffected Endpoints: 8
Total Endpoints: 9
```

### service_change.diff

```
FastAPI Endpoint Change Detector - Analysis Report
==================================================

Changes analyzed: 1 file, 3 functions modified

Affected Endpoints:
  ✓ GET    /api/users         [HIGH confidence]
    └── Changed: services/user_service.py::list_users

  ✓ GET    /api/users/{id}    [HIGH confidence]
    └── Changed: services/user_service.py::get_user_by_id

  ✓ POST   /api/users         [HIGH confidence]
    └── Changed: services/user_service.py::create_user

  ✓ PUT    /api/users/{id}    [MEDIUM confidence]
    └── Changed: services/user_service.py::get_user_by_id (shared)

  ✓ DELETE /api/users/{id}    [MEDIUM confidence]
    └── Changed: services/user_service.py::get_user_by_id (shared)

Unaffected Endpoints: 4
Total Endpoints: 9
```
