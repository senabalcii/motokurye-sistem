Okay, here are the user story requirements for User Login and Registration with JWT for the Motokurye Delivery System, formatted for GitHub Issues.

**Issue 1: User Registration - Customer**

*   **Title:** As a Customer, I want to register for an account so I can start ordering deliveries.
*   **Description:**  A customer should be able to register for an account using a form with required fields (name, surname, email, password, phone number).  The system should validate the input and create a new customer record in the database.  Upon successful registration, the customer should receive a welcome email and be automatically logged in.
*   **Labels:** `customer`, `authentication`, `registration`, `security`, `backend`, `java`, `spring-boot`, `postgresql`

*   **Acceptance Criteria:**
    *   [ ] A customer registration endpoint `/api/v1/auth/register/customer` is implemented using POST.
    *   [ ] The endpoint validates the following fields:
        *   [ ] `name`: Required, String, minimum 2 characters, maximum 50 characters.
        *   [ ] `surname`: Required, String, minimum 2 characters, maximum 50 characters.
        *   [ ] `email`: Required, String, valid email format, unique in the system.
        *   [ ] `password`: Required, String, minimum 8 characters, must contain at least one uppercase letter, one lowercase letter, one number, and one special character.
        *   [ ] `phoneNumber`: Required, String, valid Turkish phone number format (e.g., 5XXXXXXXXX).
    *   [ ] Password hashing is implemented using a strong algorithm (e.g., BCrypt).
    *   [ ] A `Customer` entity is created in the database upon successful validation and hashing.
    *   [ ] A welcome email is sent to the registered email address using a template (subject: "Welcome to Motokurye!").  The email should contain the customer's name.
    *   [ ] The system automatically logs in the user after successful registration, returning a JWT token.
    *   [ ] The API returns a success response (201 Created) with the JWT token in the response body.
    *   [ ] Error handling:
        *   [ ] Return appropriate error codes (400 Bad Request) with informative messages for invalid input.
        *   [ ] Handle duplicate email addresses (409 Conflict).
        *   [ ] Handle database connection errors (500 Internal Server Error).
*   **Edge Cases:**
    *   Attempting to register with an email address that already exists.
    *   Submitting a password that does not meet the complexity requirements.
    *   Submitting a phone number that is not in the correct format.
    *   Database connection failure during registration.
    *   Failure to send the welcome email (should be logged but not prevent registration).
    *   Request body exceeds the allowed size.

**Issue 2: User Registration - Courier**

*   **Title:** As a Courier, I want to register for an account so I can start accepting delivery requests.
*   **Description:** A courier should be able to register for an account with required fields (name, surname, email, password, phone number, vehicle type, license plate).  The system should validate the input and create a new courier record in the database. The courier account will be initially set to "inactive" and require admin approval. Upon successful registration, the courier should receive a confirmation email stating that their account is pending approval.
*   **Labels:** `courier`, `authentication`, `registration`, `security`, `backend`, `java`, `spring-boot`, `postgresql`, `admin-approval`

*   **Acceptance Criteria:**
    *   [ ] A courier registration endpoint `/api/v1/auth/register/courier` is implemented using POST.
    *   [ ] The endpoint validates the following fields:
        *   [ ] `name`: Required, String, minimum 2 characters, maximum 50 characters.
        *   [ ] `surname`: Required, String, minimum 2 characters, maximum 50 characters.
        *   [ ] `email`: Required, String, valid email format, unique in the system.
        *   [ ] `password`: Required, String, minimum 8 characters, must contain at least one uppercase letter, one lowercase letter, one number, and one special character.
        *   [ ] `phoneNumber`: Required, String, valid Turkish phone number format (e.g., 5XXXXXXXXX).
        *   [ ] `vehicleType`: Required, String, enum (e.g., "Motorcycle", "Car", "Bicycle").  Define the valid enum values.
        *   [ ] `licensePlate`: Required, String, valid Turkish license plate format (e.g., AA 123 BB).
    *   [ ] Password hashing is implemented using a strong algorithm (e.g., BCrypt).
    *   [ ] A `Courier` entity is created in the database upon successful validation and hashing. The `active` field is set to `false` by default.
    *   [ ] A confirmation email is sent to the registered email address using a template (subject: "Motokurye Courier Account Pending Approval"). The email should state that their account is pending administrator approval.
    *   [ ] The API returns a success response (201 Created).  No JWT token is returned at this stage.
    *   [ ] Error handling:
        *   [ ] Return appropriate error codes (400 Bad Request) with informative messages for invalid input.
        *   [ ] Handle duplicate email addresses (409 Conflict).
        *   [ ] Handle database connection errors (500 Internal Server Error).
*   **Edge Cases:**
    *   Attempting to register with an email address that already exists.
    *   Submitting a password that does not meet the complexity requirements.
    *   Submitting a phone number that is not in the correct format.
    *   Invalid vehicle type.
    *   Invalid license plate format.
    *   Database connection failure during registration.
    *   Failure to send the confirmation email (should be logged but not prevent registration).
    *   Request body exceeds the allowed size.

**Issue 3: User Login**

*   **Title:** As a Customer or Courier, I want to log in to the system using my credentials so I can access its features.
*   **Description:**  Registered users (both Customers and Couriers) should be able to log in using their email and password.  The system should authenticate the user and return a JWT token for authorization.
*   **Labels:** `customer`, `courier`, `authentication`, `login`, `security`, `backend`, `java`, `spring-boot`, `postgresql`, `jwt`

*   **Acceptance Criteria:**
    *   [ ] A login endpoint `/api/v1/auth/login` is implemented using POST.
    *   [ ] The endpoint accepts a JSON payload with `email` and `password` fields.
    *   [ ] The endpoint validates the presence of `email` and `password` fields.
    *   [ ] The system retrieves the user (Customer or Courier) based on the provided email.
    *   [ ] The system verifies the provided password against the stored hashed password.
    *   [ ] If authentication is successful:
        *   [ ] A JWT token is generated for the user. The token should include the user's ID, role (customer/courier), and email address.
        *   [ ] The API returns a success response (200 OK) with the JWT token in the response body.
    *   [ ] If authentication fails:
        *   [ ] The API returns an error response (401 Unauthorized) with an appropriate error message (e.g., "Invalid credentials").
    *   [ ] Courier accounts must be active to successfully login. Inactive accounts get a 403 Forbidden.
    *   [ ] Error handling:
        *   [ ] Handle the case where the user is not found (401 Unauthorized).
        *   [ ] Handle incorrect password (401 Unauthorized).
        *   [ ] Handle database connection errors (500 Internal Server Error).

*   **Edge Cases:**
    *   Invalid email address format.
    *   Incorrect password.
    *   User account does not exist.
    *   User account is locked (future feature - for too many failed login attempts).
    *   Database connection failure during authentication.
    *   Expired JWT token (covered in token refresh functionality).
    *   Courier account is not yet approved (inactive).

**Issue 4: JWT Token Handling and Validation**

*   **Title:** The system should implement JWT token handling for authentication and authorization.
*   **Description:**  The system must correctly generate, validate, and use JWT tokens for securing API endpoints.  This includes setting the token expiration time and ensuring that only authorized users can access specific resources.
*   **Labels:** `security`, `authentication`, `jwt`, `backend`, `java`, `spring-boot`, `postgresql`

*   **Acceptance Criteria:**
    *   [ ] A JWT library (e.g., `jjwt`) is integrated into the project.
    *   [ ] The system generates JWT tokens upon successful login and registration (customer).
    *   [ ] The JWT token contains the following claims:
        *   [ ] `userId`: The ID of the user.
        *   [ ] `email`: The email address of the user.
        *   [ ] `role`: The role of the user (e.g., "customer", "courier").
        *   [ ] `iat`: Issued at timestamp.
        *   [ ] `exp`: Expiration timestamp.
    *   [ ] The JWT token is signed using a secure secret key.  The secret key should be stored securely (e.g., in environment variables or a dedicated secrets management system).
    *   [ ] The token expiration time is configured (e.g., 1 hour).
    *   [ ] An authentication filter/interceptor is implemented to intercept all incoming requests.
    *   [ ] The filter/interceptor extracts the JWT token from the `Authorization` header (e.g., `Authorization: Bearer <token>`).
    *   [ ] The filter/interceptor validates the JWT token:
        *   [ ] Checks if the token is present.
        *   [ ] Verifies the token signature.
        *   [ ] Checks if the token has expired.
    *   [ ] If the token is valid, the filter/interceptor sets the user's authentication context (e.g., using `SecurityContextHolder` in Spring Security).  This allows the application to access the user's information (ID, role) in subsequent requests.
    *   [ ] If the token is invalid or missing, the filter/interceptor returns an error response (401 Unauthorized) with an appropriate error message.
    *   [ ] Specific API endpoints are secured based on user roles using Spring Security annotations (e.g., `@PreAuthorize("hasRole('customer')")`).
    *   [ ] Error handling:
        *   [ ] Handle missing JWT token (401 Unauthorized).
        *   [ ] Handle invalid JWT signature (401 Unauthorized).
        *   [ ] Handle expired JWT token (401 Unauthorized).

*   **Edge Cases:**
    *   Missing `Authorization` header.
    *   Invalid `Authorization` header format (e.g., missing "Bearer").
    *   Tampered JWT token.
    *   Expired JWT token.
    *   User tries to access a resource they are not authorized to access (e.g., a customer trying to access an admin endpoint).
    *   Secret key is compromised.

These issues provide a solid foundation for implementing user registration, login, and JWT-based authentication and authorization in your Motokurye Delivery System. Remember to refine these stories further based on your specific requirements and design choices.  Good luck!
