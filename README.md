# SecureAuth API

A professional-grade RESTful API built with **Java 21** and **Spring Boot 3**, focused on secure user authentication and authorization using **JSON Web Tokens (JWT)**.

This project demonstrates a production-ready architecture, implementing security best practices, automated documentation, and containerization.

## Technical Features

- **Java 21 (LTS):** Utilizing modern language features for clean and efficient code.
- **Spring Security 6:** Robust security configuration with stateless JWT authentication.
- **JWT (jjwt):** Implementation of Access Tokens for secure communication.
- **Database:** PostgreSQL for persistent storage with JPA/Hibernate.
- **Validation:** Strict input validation using `spring-boot-starter-validation`.
- **Global Exception Handling:** Unified error response format for better API consumption.
- **Documentation:** Interactive API documentation with **Swagger UI / OpenAPI 3**.
- **Containerization:** Ready for deployment with **Docker**.

## Architecture

The project follows a **Layered Architecture** to ensure separation of concerns, scalability, and testability.



- **Controller:** REST endpoints and request mapping.
- **Service:** Business logic and transaction management.
- **Repository:** Data access layer (Spring Data JPA).
- **Entity:** Database models.
- **DTO:** Data Transfer Objects for optimized API responses.
- **Security:** JWT filters and Authentication Providers.

## Tech Stack

* **Language:** Java 21
* **Framework:** Spring Boot 3.x
* **Security:** Spring Security, JJWT
* **Database:** PostgreSQL
* **Persistence:** Spring Data JPA / Hibernate
* **Documentation:** SpringDoc OpenAPI
* **Build Tool:** Maven

## API Endpoints

All endpoints are grouped under `/api/auth/` and `/api/user/`.

### Authentication
| Method | Endpoint | Description | Access |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/auth/register` | Register a new user | Public |
| `POST` | `/api/auth/login` | Login and get JWT token | Public |
| `POST` | `/api/auth/logout` | Invalidates the refresh token and revokes the session | Authenticated |
| `POST` | `/api/auth/refresh` | Refreshes access and refresh tokens using a valid refresh token | Authenticated |
| `POST` | `/api/auth/newPassword` | Changes the password of the authenticated user and returns renewed tokens | Authenticated |

### Users
| Method | Endpoint | Description | Access |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/user/all` | List all users | Admin |
| `GET` | `/api/user/{userId}` | Get user details | Admin |
| `PUT` | `/api/user/update/{userId}` | Update user profile information | Admin / Owner |
| `PUT` | `/api/user/role/{userId}` | Update a user's role | Admin |
| `PUT` | `/api/user/delete/{userId}` | Perform a virtual delete (soft delete) | Admin / Owner |
| `PUT` | `/api/user/active/{userId}` | Reactivate a user | Admin |
| `DELETE` | `/api/user/permanentlyDelete/{userId}` | Permanently delete a user | Admin |

## Validation Rules

The API uses Bean Validation for request payloads. The most relevant rules are:

### Authentication Requests
| DTO | Field | Validation |
| :--- | :--- | :--- |
| `LoginRequest` | `username` | Required. Minimum 3 characters, maximum 100. The service accepts username or email in this field. |
| `LoginRequest` | `password` | Required. Minimum 8 characters, maximum 255. |
| `CreateUserRequest` | `email` | Required and must be a valid email address. |
| `CreateUserRequest` | `username` | Required. Minimum 3 characters, maximum 100. |
| `CreateUserRequest` | `name` | Optional. Maximum 255 characters. |
| `CreateUserRequest` | `surname` | Optional. Maximum 255 characters. |
| `CreateUserRequest` | `password` | Required. Minimum 8 characters, maximum 255. |
| `NewPasswordUserRequest` | `token` | Required. Minimum 20 characters, maximum 500. This is the refresh token used to authorize the password change. |
| `NewPasswordUserRequest` | `newPassword` | Required. Minimum 8 characters, maximum 255. |
| `NewPasswordUserRequest` | `confirmPassword` | Required. Minimum 8 characters, maximum 255. Must match `newPassword`. |

### User Management Requests
| DTO | Field | Validation |
| :--- | :--- | :--- |
| `UpdateUserProfileRequest` | `username` | Optional. Minimum 3 characters, maximum 100. |
| `UpdateUserProfileRequest` | `name` | Optional. Maximum 255 characters. |
| `UpdateUserProfileRequest` | `surname` | Optional. Maximum 255 characters. |
| `UpdateUserRoleRequest` | `roleName` | Validation only checks length, maximum 20 characters. The endpoint expects a role name to perform the update. |

Validation errors return a standard JSON payload with `timestamp`, `status`, `error`, `message`, and, when applicable, an `errors` object with field-level messages.

## Local Setup

1. **Clone the repo:**
   ```bash
   git clone [https://github.com/IvanSM-Hub/SecureAuth-API.git](https://github.com/IvanSM-Hub/SecureAuth-API.git)
