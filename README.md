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

### Authentication
| Method | Endpoint | Description | Access |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/auth/register` | Register a new user | Public |
| `POST` | `/api/auth/login` | Login and get JWT token | Public |
| `POST` | `/api/auth/logout` | Invalidates the JWT token and session too | Private |
| `POST` | `/api/auth/refresh` | Refresh the JWT token from the user and keeps the session valitade | Private |
| `POST` | `/api/auth/newPassword` | The user can change the password, if he had the token from his session | Private |

### Users
| Method | Endpoint | Description | Access |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/user/all` | List all users | Admin |
| `GET` | `/api/user/{id}` | Get user details | Admin / Owner |
| `PUT` | `/api/user/{id}` | Post to modify the user information | Admin / Owner |
| `PUT` | `/api/user/{id}` | Post to modify the user role | Admin |
| `DELETE` | `/api/users/{id}` | Delete a user | Admin |

## Local Setup

1. **Clone the repo:**
   ```bash
   git clone [https://github.com/IvanSM-Hub/SecureAuth-API.git](https://github.com/IvanSM-Hub/SecureAuth-API.git)
