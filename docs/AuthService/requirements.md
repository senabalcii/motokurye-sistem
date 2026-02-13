Okay, here are the user story and acceptance criteria for user login and registration with JWT (JSON Web Token) for the Motokurye Delivery System.  This focuses on the backend implementation with Java/Spring Boot and PostgreSQL.

**GitHub Issue:**

**Title:** Implement User Login and Registration with JWT Authentication

**Description:**

As a developer, I need to implement secure user login and registration functionality, leveraging JWT (JSON Web Token) for authentication and authorization.  This will allow customers, couriers, and admins to access the Motokurye Delivery System with appropriate permissions based on their roles.  This issue encompasses user registration, login, password hashing, JWT generation, and token verification. It should cover error scenarios, input validation, and secure password handling.

**Labels:** `authentication`, `security`, `user management`, `backend`, `java`, `spring-boot`, `jwt`, `database`

**User Story:**

*   As a **customer**, I want to be able to register for an account using my email and password so that I can place delivery orders.
*   As a **courier**, I want to be able to register for an account using my phone number and license plate so that I can accept and fulfill delivery orders.
*   As an **admin**, I want to be able to register for an account using an email and password so that I can manage the system.
*   As a **user (customer, courier, or admin)**, I want to be able to log in to the system using my credentials so that I can access the features relevant to my role.
*   As a **developer**, I want the system to securely store user credentials (passwords) so that they are protected from unauthorized access.
*   As a **developer**, I want the system to use JWT for authentication and authorization so that access to resources is controlled based on user roles and permissions.
*   As a **developer**, I want the system to handle invalid login attempts and registration errors gracefully so that users receive informative feedback.

**Acceptance Criteria:**

- [ ] **Registration Endpoint:**
    - [ ] Implement a `/register` endpoint that accepts user registration data (email/phone, password, role).
    - [ ] Validate user input:
        - [ ] Email format (for customer and admin)
        - [ ] Phone number format (for courier)
        - [ ] Password strength (minimum length, complexity)
        - [ ] License plate format (for courier)
    - [ ] Check for existing users with the same email (customer, admin) or phone number (courier). Return an appropriate error message if a user already exists.
    - [ ] Hash the user's password using a strong hashing algorithm (e.g., bcrypt) before storing it in the database.
    - [ ] Store the user information (including the hashed password and role) in the `users` table.
    - [ ] Return a success response (HTTP 201 Created) upon successful registration.  Include basic user information (without sensitive data like password) in the response.
    - [ ] Handle database connection errors gracefully.
- [ ] **Login Endpoint:**
    - [ ] Implement a `/login` endpoint that accepts user credentials (email/phone and password).
    - [ ] Retrieve the user from the database based on the provided email or phone number.
    - [ ] Verify the provided password against the hashed password stored in the database using the same hashing algorithm.
    - [ ] If authentication is successful:
        - [ ] Generate a JWT containing:
            - [ ] User ID
            - [ ] User Role (customer, courier, admin)
            - [ ] Issue Time
            - [ ] Expiration Time (short-lived, e.g., 15 minutes)
        - [ ] Return the JWT in the response body (HTTP 200 OK).
    - [ ] If authentication fails:
        - [ ] Return an appropriate error message (e.g., "Invalid credentials") and HTTP status code (e.g., 401 Unauthorized).
    - [ ] Implement a refresh token mechanism to allow users to refresh their JWT token without re-entering their credentials.
    - [ ]  Handle account locking after multiple failed login attempts (optional for initial implementation, but recommended).
- [ ] **JWT Configuration:**
    - [ ] Define a secret key for signing JWTs. **This key MUST be stored securely (e.g., in environment variables or a dedicated secrets management system) and NOT hardcoded in the application.**
    - [ ] Configure JWT expiration time.
    - [ ] Implement a filter or interceptor to validate the JWT on protected endpoints.
        - [ ] Check for the presence of the JWT in the `Authorization` header (e.g., `Bearer <token>`).
        - [ ] Verify the JWT's signature using the secret key.
        - [ ] Extract user information (user ID, role) from the JWT's payload.
        - [ ] If the JWT is invalid or expired, return an appropriate error message (e.g., "Invalid token" or "Token expired") and HTTP status code (e.g., 401 Unauthorized).
        - [ ] Set the user's authentication context (e.g., using `SecurityContextHolder` in Spring Security) so that the application knows which user is making the request.
- [ ] **Role-Based Authorization:**
    - [ ] Implement role-based authorization to restrict access to certain endpoints based on the user's role (customer, courier, admin).  This can be achieved using Spring Security annotations (e.g., `@PreAuthorize("hasRole('CUSTOMER')")`).
    - [ ] Define the roles and their corresponding permissions in the application's configuration.
    - [ ] Ensure that unauthorized users are denied access to protected endpoints and receive an appropriate error message (e.g., "Forbidden" or "Unauthorized") and HTTP status code (e.g., 403 Forbidden).
- [ ] **Error Handling:**
    - [ ] Implement global exception handling to catch exceptions related to authentication and authorization (e.g., `AuthenticationException`, `AccessDeniedException`).
    - [ ] Return consistent and informative error messages in a standardized format (e.g., JSON).
    - [ ] Log all authentication and authorization errors for auditing and debugging purposes.
- [ ] **Database Schema Considerations:**
    - [ ] The `users` table should include the following columns:
        - [ ] `id` (BIGSERIAL, primary key)
        - [ ] `email` (VARCHAR, unique, nullable for couriers)
        - [ ] `phone_number` (VARCHAR, unique, nullable for customers and admins)
        - [ ] `password_hash` (VARCHAR, stores the hashed password)
        - [ ] `role` (ENUM: `customer`, `courier`, `admin`)
        - [ ] `license_plate` (VARCHAR, nullable, only for couriers)
        - [ ] `created_at` (TIMESTAMP WITH TIME ZONE, default: `now()`)
        - [ ] `updated_at` (TIMESTAMP WITH TIME ZONE, default: `now()`)

**Edge Cases / Considerations:**

*   **Password Reset:**  A separate user story should cover password reset functionality (email verification, token generation, etc.).
*   **Account Verification:**  Consider adding email/phone verification steps during registration to ensure the user provides valid contact information.
*   **Rate Limiting:** Implement rate limiting on the login endpoint to prevent brute-force attacks.
*   **Security Headers:**  Include appropriate security headers in the responses (e.g., `X-Content-Type-Options`, `X-Frame-Options`, `Strict-Transport-Security`).
*   **Session Management:** While JWTs are stateless, you might want to implement a mechanism to revoke tokens (e.g., store revoked token IDs in a blacklist).
*   **Refresh Token Rotation:** Implement refresh token rotation for enhanced security.  Each time a refresh token is used, a new refresh token is issued, and the old refresh token is invalidated.
*   **GDPR Compliance:**  Consider data privacy regulations (like GDPR) when handling user data.
*   **Testing:**  Write thorough unit and integration tests to cover all aspects of the authentication and authorization functionality.  Include tests for successful login, failed login, registration errors, JWT validation, and role-based access control.
*   **Scalability:** Consider the scalability of the authentication system, especially if you anticipate a large number of users. Caching and database optimization may be necessary.
*   **Observability:** Implement proper logging and monitoring to track authentication events and detect potential security issues.

This detailed user story provides a solid foundation for implementing user login and registration with JWT in the Motokurye Delivery System. Remember to break down this large user story into smaller, more manageable tasks during development. Good luck!
