Okay, let's design the architecture for user login and registration with JWT for the Motokurye Delivery System based on the provided user story and acceptance criteria.

**I. Project Structure (Maven)**

```
motokurye-delivery-system/
├── pom.xml
└── src/
    ├── main/
    │   ├── java/
    │   │   └── com/
    │   │       └── motokurye/
    │   │           └── delivery/
    │   │               ├── MotokuryeDeliverySystemApplication.java (Main application class)
    │   │               ├── config/
    │   │               │   ├── SecurityConfig.java (Spring Security configuration)
    │   │               │   ├── JwtConfig.java (JWT specific configuration)
    │   │               ├── controller/
    │   │               │   ├── AuthenticationController.java (Handles login/registration endpoints)
    │   │               │   ├── UserController.java (Example protected endpoint)
    │   │               ├── dto/
    │   │               │   ├── RegisterRequest.java (Registration DTO)
    │   │               │   ├── LoginRequest.java (Login DTO)
    │   │               │   ├── AuthenticationResponse.java (JWT response DTO)
    │   │               │   ├── UserDTO.java (DTO for returning User information)
    │   │               ├── entity/
    │   │               │   ├── User.java (User entity)
    │   │               ├── enums/
    │   │               │   ├── Role.java (Enum for user roles)
    │   │               ├── exception/
    │   │               │   ├── GlobalExceptionHandler.java (Handles exceptions)
    │   │               │   ├── UserAlreadyExistsException.java
    │   │               │   ├── InvalidCredentialsException.java
    │   │               ├── filter/
    │   │               │   ├── JwtAuthenticationFilter.java (Validates JWTs)
    │   │               ├── repository/
    │   │               │   ├── UserRepository.java (Database access for users)
    │   │               ├── service/
    │   │               │   ├── AuthenticationService.java (Business logic for auth)
    │   │               │   ├── UserService.java (Business logic for user operations)
    │   │               │   ├── JwtService.java (JWT token generation/validation)
    │   │               └── util/
    │   │                   └── PasswordUtils.java (Password hashing utility)
    │   └── resources/
    │       ├── application.properties (or application.yml)
    │       └── db/migration/ (Flyway or Liquibase migrations)
    └── test/
        └── java/
            └── com/
                └── motokurye/
                    └── delivery/
                        ├── AuthenticationControllerTest.java
                        ├── UserRepositoryTest.java
                        └── ...
```

**II. Database Schema (PostgreSQL)**

```sql
CREATE TYPE user_role AS ENUM ('customer', 'courier', 'admin');

CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NULL,
    phone_number VARCHAR(20) UNIQUE NULL,
    password_hash VARCHAR(255) NOT NULL,
    role user_role NOT NULL,
    license_plate VARCHAR(20) NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT email_or_phone CHECK (
        (email IS NOT NULL AND phone_number IS NULL) OR
        (email IS NULL AND phone_number IS NOT NULL)
    )
);

CREATE INDEX idx_users_email ON users (email);
CREATE INDEX idx_users_phone_number ON users (phone_number);
CREATE INDEX idx_users_role ON users (role);


-- Example Migration (using Flyway) - V1__create_users_table.sql
-- V1 is the version and __create_users_table.sql is the description of the migration.  This will be run automatically by Flyway on startup if the table doesn't exist or if the schema_version table says this migration hasn't been applied.

```

**III. Java Domain Model (Entities)**

```java
package com.motokurye.delivery.entity;

import com.motokurye.delivery.enums.Role;
import jakarta.persistence.*;
import lombok.Data;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.OffsetDateTime;

@Entity
@Table(name = "users")
@Data // Lombok for getters, setters, equals, hashCode, toString
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true)
    private String email;

    @Column(unique = true)
    private String phoneNumber;

    @Column(nullable = false)
    private String passwordHash;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Role role;

    private String licensePlate; // Only for couriers

    @CreationTimestamp
    @Column(updatable = false)
    private OffsetDateTime createdAt;

    @UpdateTimestamp
    private OffsetDateTime updatedAt;
}
```

**IV. RESTful API Endpoints and DTOs**

```java
package com.motokurye.delivery.dto;

import lombok.Data;

@Data
public class RegisterRequest {
    private String email;       // For customer and admin
    private String phoneNumber; // For courier
    private String password;
    private String role;        // "customer", "courier", "admin"
    private String licensePlate;  // Only for courier, optional
}

package com.motokurye.delivery.dto;

import lombok.Data;

@Data
public class LoginRequest {
    private String email;
    private String phoneNumber;
    private String password;
}


package com.motokurye.delivery.dto;

import lombok.Data;

@Data
public class AuthenticationResponse {
    private String token;
}

package com.motokurye.delivery.dto;

import lombok.Data;

@Data
public class UserDTO {
    private Long id;
    private String email;
    private String phoneNumber;
    private String role;
    private String licensePlate;
}
```

```java
package com.motokurye.delivery.controller;

import com.motokurye.delivery.dto.RegisterRequest;
import com.motokurye.delivery.dto.LoginRequest;
import com.motokurye.delivery.dto.AuthenticationResponse;
import com.motokurye.delivery.service.AuthenticationService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    public AuthenticationController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest registerRequest) {
        try {
            UserDTO registeredUser = authenticationService.register(registerRequest);
            return new ResponseEntity<>(registeredUser, HttpStatus.CREATED);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage()); // Or a more structured error response
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
        try {
            AuthenticationResponse response = authenticationService.login(loginRequest);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage()); // Or a more structured error
        }
    }
}
```

**V. Security (JWT/Spring Security)**

*   **JwtConfig.java:** Configuration for JWT secret, expiration time, etc.  The secret should be read from environment variables.
*   **JwtService.java:**  Handles JWT generation and validation using `io.jsonwebtoken`.
*   **JwtAuthenticationFilter.java:**  A `OncePerRequestFilter` that intercepts requests, validates the JWT from the `Authorization` header, and sets the authentication context in Spring Security.
*   **SecurityConfig.java:**  Spring Security configuration:
    *   Configures authentication manager.
    *   Defines URL patterns that are publicly accessible (e.g., `/api/auth/register`, `/api/auth/login`).
    *   Defines URL patterns that require authentication and authorization based on roles (e.g., `/api/admin/**` requires `ADMIN` role).
    *   Registers the `JwtAuthenticationFilter` to be used.
    *   Configures CORS.

**VI. Implementation Details & Considerations**

*   **Password Hashing:** Use `BCryptPasswordEncoder` in Spring Security.  Example:

    ```java
    import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

    @Service
    public class AuthenticationService {

        private final UserRepository userRepository;
        private final BCryptPasswordEncoder passwordEncoder;

        public AuthenticationService(UserRepository userRepository, BCryptPasswordEncoder passwordEncoder) {
            this.userRepository = userRepository;
            this.passwordEncoder = passwordEncoder;
        }

        public UserDTO register(RegisterRequest registerRequest) {
            // ... validation ...

            User user = new User();
            //... set user properties from registerRequest
            user.setPasswordHash(passwordEncoder.encode(registerRequest.getPassword()));
            //...

            User savedUser = userRepository.save(user);

            return convertToDto(savedUser);
        }

        public AuthenticationResponse login(LoginRequest loginRequest) {
            //...
            User user = findUserByEmailOrPhone(loginRequest); //Implement this method in your service.
            if (user != null && passwordEncoder.matches(loginRequest.getPassword(), user.getPasswordHash())) {
                //...generate JWT
            } else {
                throw new InvalidCredentialsException("Invalid credentials");
            }
            //...
        }
    }
    ```

*   **Role-Based Authorization:**  Use `@PreAuthorize` annotation in controllers:

    ```java
    import org.springframework.security.access.prepost.PreAuthorize;
    import org.springframework.web.bind.annotation.GetMapping;
    import org.springframework.web.bind.annotation.RequestMapping;
    import org.springframework.web.bind.annotation.RestController;

    @RestController
    @RequestMapping("/api/admin")
    public class AdminController {

        @GetMapping("/dashboard")
        @PreAuthorize("hasRole('ADMIN')")
        public String adminDashboard() {
            return "Admin Dashboard";
        }
    }
    ```

*   **Error Handling:** Implement `GlobalExceptionHandler` to handle exceptions like `UserAlreadyExistsException`, `AuthenticationException`, `AccessDeniedException`, `InvalidCredentialsException`. Return consistent JSON error responses.  Example:

    ```java
    import org.springframework.http.HttpStatus;
    import org.springframework.http.ResponseEntity;
    import org.springframework.web.bind.annotation.ControllerAdvice;
    import org.springframework.web.bind.annotation.ExceptionHandler;

    @ControllerAdvice
    public class GlobalExceptionHandler {

        @ExceptionHandler(UserAlreadyExistsException.class)
        public ResponseEntity<String> handleUserAlreadyExistsException(UserAlreadyExistsException ex) {
            return new ResponseEntity<>(ex.getMessage(), HttpStatus.CONFLICT);
        }

        @ExceptionHandler(InvalidCredentialsException.class)
        public ResponseEntity<String> handleInvalidCredentialsException(InvalidCredentialsException ex) {
            return new ResponseEntity<>(ex.getMessage(), HttpStatus.UNAUTHORIZED);
        }

        // Add other exception handlers as needed
    }
    ```

*   **Input Validation:** Use `@Valid` annotation and `javax.validation` annotations in DTOs.

    ```java
    import jakarta.validation.constraints.Email;
    import jakarta.validation.constraints.NotBlank;
    import jakarta.validation.constraints.Size;
    import lombok.Data;

    @Data
    public class RegisterRequest {

        @Email(message = "Invalid email format")
        private String email;

        @NotBlank(message = "Password is required")
        @Size(min = 8, message = "Password must be at least 8 characters long")
        private String password;

        //... other fields
    }
    ```

*   **Database Indexing:**  Indexes on `email`, `phone_number`, and `role` columns in the `users` table for faster lookups.

*   **Logging:**  Use SLF4J for logging authentication events, errors, and security-related information.

*   **Refresh Token (basic):**

    1.  Store the refresh token in a secure (HttpOnly) cookie or in the database (linked to the user).  Storing in a cookie mitigates XSS attacks.  Storing in the database allows for easy revocation.
    2.  Create a `/refresh-token` endpoint.
    3.  Upon receiving a request to `/refresh-token`:
        *   Validate the refresh token.
        *   If valid, generate a new JWT and a new refresh token.
        *   Return the new JWT and refresh token.

*   **Refresh Token Rotation (advanced):**
    1. When a user logs in, generate an access token and a refresh token.  Store the refresh token securely (e.g., in a database or a secure cookie).
    2.  When the access token expires, the client sends the refresh token to the `/refresh` endpoint.
    3.  The server validates the refresh token.
    4.  If the refresh token is valid:
        *   The server generates a *new* refresh token and a new access token.
        *   The *old* refresh token is invalidated (e.g., by deleting it from the database or adding it to a blacklist).
        *   The new refresh token is stored securely.
    5.  The new access token and refresh token are returned to the client.

    This approach prevents refresh token theft from being useful for more than one access token.  If a refresh token is stolen and used, the legitimate user's next refresh request will invalidate the stolen token, effectively mitigating the attack.

*   **Account Locking:** Implement a mechanism to lock accounts after a certain number of failed login attempts (store the number of failed attempts and a timestamp in the database).

*   **CORS Configuration:**  Properly configure CORS to allow requests from your frontend application's origin.

*   **Environment Variables:** Store sensitive information like the JWT secret key and database credentials in environment variables.

*   **Testing:** Write unit tests for individual components (services, filters) and integration tests for the entire authentication flow.

This architecture provides a solid foundation for building a secure and scalable authentication system for the Motokurye Delivery System.  Remember to adapt and refine it based on your specific requirements and constraints.
