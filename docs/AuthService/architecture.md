Okay, here's the architectural design for the Motokurye Delivery System, focusing on User Registration, Login, and JWT-based Authentication, according to the provided user stories.

**1. Database Schema (PostgreSQL)**

```sql
CREATE TABLE customer (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(50) NOT NULL,
    surname VARCHAR(50) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,  -- Hashed password
    phone_number VARCHAR(15) NOT NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT (NOW() at time zone 'utc')
);

CREATE TABLE courier (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(50) NOT NULL,
    surname VARCHAR(50) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,  -- Hashed password
    phone_number VARCHAR(15) NOT NULL,
    vehicle_type VARCHAR(50) NOT NULL,  --ENUM('Motorcycle', 'Car', 'Bicycle') or string
    license_plate VARCHAR(20) NOT NULL,
    active BOOLEAN NOT NULL DEFAULT FALSE, -- Indicates if the courier is approved/active
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT (NOW() at time zone 'utc')
);

-- Consider a separate table for user roles if more roles are needed in the future
CREATE TABLE role (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL
);

CREATE TABLE user_role (
    user_id BIGINT NOT NULL,
    role_id INTEGER NOT NULL,
    user_type VARCHAR(10) NOT NULL, -- 'customer' or 'courier'
    PRIMARY KEY (user_id, role_id, user_type),
    CONSTRAINT fk_user_role_customer
      FOREIGN KEY(user_id) REFERENCES customer(id),
    CONSTRAINT fk_user_role_courier
      FOREIGN KEY(user_id) REFERENCES courier(id),
    CONSTRAINT fk_user_role_role
      FOREIGN KEY(role_id) REFERENCES role(id)
);

-- Indexes for performance
CREATE INDEX idx_customer_email ON customer (email);
CREATE INDEX idx_courier_email ON courier (email);

-- Example Roles
INSERT INTO role (name) VALUES ('customer');
INSERT INTO role (name) VALUES ('courier');
INSERT INTO role (name) VALUES ('admin');
```

**Explanation:**

*   **customer Table:** Stores customer information.  `email` is unique.
*   **courier Table:** Stores courier information. `active` flag determines if the courier is approved. `vehicle_type` can be an enum or a string field.
*   **role Table:** Stores roles.
*   **user_role Table:** Many-to-many relationship between users (customer/courier) and roles.  This allows for future expansion with different roles (e.g., admin).  The `user_type` column clarifies if the user is a customer or a courier.
*   **Indexes:**  `idx_customer_email` and `idx_courier_email` indexes speed up user lookups during login.

**2. Java Domain Model (Entities)**

```java
// src/main/java/com/motokurye/motokuryedelivery/model

import jakarta.persistence.*;
import lombok.Data;
import java.time.LocalDateTime;

@Entity
@Table(name = "customer")
@Data
public class Customer {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 50)
    private String name;

    @Column(nullable = false, length = 50)
    private String surname;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false, name = "phone_number")
    private String phoneNumber;

    @Column(name = "created_at")
    private LocalDateTime createdAt;
}
```

```java
// src/main/java/com/motokurye/motokuryedelivery/model
import jakarta.persistence.*;
import lombok.Data;
import java.time.LocalDateTime;

@Entity
@Table(name = "courier")
@Data
public class Courier {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 50)
    private String name;

    @Column(nullable = false, length = 50)
    private String surname;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false, name = "phone_number")
    private String phoneNumber;

    @Column(nullable = false, name = "vehicle_type")
    private String vehicleType; // Consider using an enum

    @Column(nullable = false, name = "license_plate")
    private String licensePlate;

    @Column(nullable = false)
    private Boolean active;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

}
```

```java
// src/main/java/com/motokurye/motokuryedelivery/model

import jakarta.persistence.*;
import lombok.Data;
import java.util.Set;

@Entity
@Table(name = "role")
@Data
public class Role {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column(nullable = false, unique = true)
    private String name;

    //Consider many-to-many relationships if required
    //@ManyToMany(mappedBy = "roles")
    //private Set<User> users;
}
```

```java
// src/main/java/com/motokurye/motokuryedelivery/model

import jakarta.persistence.*;
import lombok.Data;

@Entity
@Table(name = "user_role")
@Data
public class UserRole {

    @EmbeddedId
    private UserRoleId id;

    @ManyToOne
    @MapsId("userId")
    @JoinColumn(name = "user_id")
    private Customer customer; //Can be Customer or Courier. Consider using an interface

    @ManyToOne
    @MapsId("roleId")
    @JoinColumn(name = "role_id")
    private Role role;

    @Column(name = "user_type", nullable = false)
    private String userType; // "customer" or "courier"
}
```

```java
// src/main/java/com/motokurye/motokuryedelivery/model

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import lombok.Data;

import java.io.Serializable;

@Embeddable
@Data
public class UserRoleId implements Serializable {

    @Column(name = "user_id")
    private Long userId;

    @Column(name = "role_id")
    private Integer roleId;

    @Column(name = "user_type")
    private String userType;
}
```

**Explanation:**

*   Uses JPA annotations for entity mapping.
*   `@Data` (from Lombok) generates getters, setters, `equals()`, `hashCode()`, and `toString()`.
*   `@Table` specifies the database table name.
*   `@Column` defines column properties.
*   `@Id`, `@GeneratedValue` define the primary key and its generation strategy.
*   `@UniqueConstraint` enforces unique email addresses.
*   UserRole and UserRoleId are needed for composite primary key.

**3. RESTful API Endpoints & DTOs**

```java
// src/main/java/com/motokurye/motokuryedelivery/dto

import jakarta.validation.constraints.*;
import lombok.Data;

@Data
public class CustomerRegistrationRequest {
    @NotBlank(message = "Name is required")
    @Size(min = 2, max = 50, message = "Name must be between 2 and 50 characters")
    private String name;

    @NotBlank(message = "Surname is required")
    @Size(min = 2, max = 50, message = "Surname must be between 2 and 50 characters")
    private String surname;

    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    private String email;

    @NotBlank(message = "Password is required")
    @Pattern(regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$",
            message = "Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character")
    private String password;

    @NotBlank(message = "Phone number is required")
    @Pattern(regexp = "^5[0-9]{9}$", message = "Invalid Turkish phone number format")
    private String phoneNumber;
}
```

```java
// src/main/java/com/motokurye/motokuryedelivery/dto

import jakarta.validation.constraints.*;
import lombok.Data;

@Data
public class CourierRegistrationRequest {
    @NotBlank(message = "Name is required")
    @Size(min = 2, max = 50, message = "Name must be between 2 and 50 characters")
    private String name;

    @NotBlank(message = "Surname is required")
    @Size(min = 2, max = 50, message = "Surname must be between 2 and 50 characters")
    private String surname;

    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    private String email;

    @NotBlank(message = "Password is required")
    @Pattern(regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$",
            message = "Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character")
    private String password;

    @NotBlank(message = "Phone number is required")
    @Pattern(regexp = "^5[0-9]{9}$", message = "Invalid Turkish phone number format")
    private String phoneNumber;

    @NotBlank(message = "Vehicle type is required")
    private String vehicleType; // Or use an enum

    @NotBlank(message = "License plate is required")
    @Pattern(regexp = "^[A-Z]{1,3} \\d{2,4} [A-Z]{2,3}$", message = "Invalid Turkish license plate format")
    private String licensePlate;
}
```

```java
// src/main/java/com/motokurye/motokuryedelivery/dto
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class LoginRequest {

    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    private String email;

    @NotBlank(message = "Password is required")
    private String password;
}
```

```java
// src/main/java/com/motokurye/motokuryedelivery/dto

import lombok.Data;

@Data
public class JwtResponse {
    private String token;
    private String type = "Bearer";

    public JwtResponse(String token) {
        this.token = token;
    }
}
```

```java
// src/main/java/com/motokurye/motokuryedelivery/controller
import com.motokurye.motokuryedelivery.dto.*;
import com.motokurye.motokuryedelivery.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register/customer")
    public ResponseEntity<?> registerCustomer(@Valid @RequestBody CustomerRegistrationRequest registrationRequest) {
        JwtResponse jwtResponse = authService.registerCustomer(registrationRequest);
        return new ResponseEntity<>(jwtResponse, HttpStatus.CREATED);
    }

    @PostMapping("/register/courier")
    public ResponseEntity<?> registerCourier(@Valid @RequestBody CourierRegistrationRequest registrationRequest) {
        authService.registerCourier(registrationRequest);
        return new ResponseEntity<>(HttpStatus.CREATED);
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest loginRequest) {
        JwtResponse jwtResponse = authService.login(loginRequest);
        return ResponseEntity.ok(jwtResponse);
    }
}
```

**API Endpoints:**

*   `POST /api/v1/auth/register/customer`: Registers a new customer.  Returns 201 Created with JWT in body.
*   `POST /api/v1/auth/register/courier`: Registers a new courier. Returns 201 Created.
*   `POST /api/v1/auth/login`: Logs in a user (customer or courier). Returns 200 OK with JWT in body.

**DTOs:**

*   `CustomerRegistrationRequest`:  Data transfer object for customer registration. Includes validation annotations.
*   `CourierRegistrationRequest`: Data transfer object for courier registration. Includes validation annotations.
*   `LoginRequest`: Data transfer object for login.
*   `JwtResponse`:  Data transfer object for the JWT token returned upon successful login/registration.

**4. Maven Project Structure**

```
motokurye-delivery/
├── pom.xml
└── src/
    └── main/
        ├── java/
        │   └── com/motokurye/motokuryedelivery/
        │       ├── MotokuryeDeliveryApplication.java (Main Application Class)
        │       ├── controller/
        │       │   └── AuthController.java
        │       ├── model/
        │       │   ├── Customer.java
        │       │   ├── Courier.java
        │       │   ├── Role.java
        │       │   ├── UserRole.java
        │       │   └── UserRoleId.java
        │       ├── dto/
        │       │   ├── CustomerRegistrationRequest.java
        │       │   ├── CourierRegistrationRequest.java
        │       │   ├── LoginRequest.java
        │       │   └── JwtResponse.java
        │       ├── repository/
        │       │   ├── CustomerRepository.java
        │       │   ├── CourierRepository.java
        │       │   ├── RoleRepository.java
        │       │   └── UserRoleRepository.java
        │       ├── service/
        │       │   ├── AuthService.java
        │       │   └── JwtService.java
        │       ├── config/
        │       │   ├── SecurityConfig.java
        │       │   └── ApplicationConfig.java
        │       ├── security/
        │       │   └── JwtAuthenticationFilter.java
        │       └── exception/
        │           ├── GlobalExceptionHandler.java
        │           └── CustomException.java
        │
        ├── resources/
        │   ├── application.properties (or application.yml)
        │   └── templates/
        │       └── welcome_email.html
        │       └── courier_pending_approval_email.html
        └── test/
            └── java/
                └── com/motokurye/motokuryedelivery/
                    └── AuthControllerIntegrationTest.java
```

**5. Security (JWT/Spring Security)**

*   **JWT Library:** Use `jjwt` (io.jsonwebtoken:jjwt-api, jjwt-impl, jjwt-jackson) or similar.
*   **Secret Key:** Store the JWT secret key in a secure environment variable, *not* in the code.
*   **`JwtService`:** A service class responsible for:
    *   Generating JWT tokens (using user details: ID, email, roles).
    *   Validating JWT tokens (verifying signature and expiration).
    *   Extracting user information from the token.
*   **`JwtAuthenticationFilter`:** A Spring Security filter that intercepts all requests:
    1.  Extracts the JWT token from the `Authorization` header.
    2.  Validates the token using `JwtService`.
    3.  If the token is valid, sets the authentication context using `SecurityContextHolder`.  This involves creating an `Authentication` object with the user's details and roles.
*   **`SecurityConfig`:** A Spring Security configuration class:
    *   Configures the filter chain to use the `JwtAuthenticationFilter`.
    *   Defines which endpoints are protected and which roles are allowed to access them using `@PreAuthorize` annotations on controllers or methods.
    *   Configures password encoding (BCrypt).
*   **Password Hashing:** Use BCryptPasswordEncoder.

**Example `SecurityConfig`:**

```java
// src/main/java/com/motokurye/motokuryedelivery/config

import com.motokurye.motokuryedelivery.security.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableMethodSecurity
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests((authorize) -> authorize
                        .requestMatchers("/api/v1/auth/**").permitAll() // Allow authentication endpoints
                        .anyRequest().authenticated() // Require authentication for all other endpoints
                )
                .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // Stateless session
                )
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
```

**Example `JwtAuthenticationFilter`:**

```java
// src/main/java/com/motokurye/motokuryedelivery/security
import com.motokurye.motokuryedelivery.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }
        jwt = authHeader.substring(7);
        userEmail = jwtService.extractUsername(jwt);
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
            if (jwtService.isTokenValid(jwt, userDetails)) {
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        filterChain.doFilter(request, response);
    }
}
```

**6. Database Indexing**

*   Indexes on `email` columns in both `customer` and `courier` tables are crucial for fast user lookups during login and registration (to check for duplicate emails).  These are already included in the schema above.
*   Consider indexing other columns used in frequent queries (e.g., `license_plate` in the `courier` table if you often search by license plate).

**7. Error Handling**

*   **Global Exception Handler:**  Create a `@ControllerAdvice` class to handle exceptions globally:
    *   Catch `MethodArgumentNotValidException` for validation errors and return 400 Bad Request with detailed error messages.
    *   Catch `DuplicateKeyException` (or similar depending on your database driver) for duplicate email addresses and return 409 Conflict.
    *   Catch generic `Exception` and log the error, returning 500 Internal Server Error.
*   **Specific Exception Handling:**  Within the service layer, catch exceptions related to database operations or sending emails and handle them appropriately (e.g., log the email sending failure).

**8. Email Sending**

*   Use Spring's `JavaMailSender` to send emails.
*   Use a templating engine (e.g., Thymeleaf) to create dynamic email content from HTML templates.
*   Configure email sending properties in `application.properties` (or `application.yml`).
*   Email sending should be asynchronous (e.g., using `@Async`) to avoid blocking the main thread.  Log any email sending failures.

**9. Validation**

*   Use `@Valid` annotation with DTOs to trigger validation.
*   Use validation annotations from `jakarta.validation.constraints` (e.g., `@NotBlank`, `@Email`, `@Size`, `@Pattern`).
*   Implement custom validators if needed for more complex validation rules.

**10. Considerations for Scalability and Robustness**

*   **Statelessness:**  JWT-based authentication inherently supports statelessness, which is essential for scalability.
*   **Database Connection Pooling:**  Use a connection pool (e.g., HikariCP) to efficiently manage database connections.
*   **Caching:** Cache frequently accessed data (e.g., user roles) to reduce database load.
*   **Load Balancing:**  Distribute traffic across multiple instances of the application.
*   **Monitoring and Logging:**  Implement comprehensive monitoring and logging to detect and diagnose issues.
*   **Externalized Configuration:**  Use environment variables or a configuration server (e.g., Spring Cloud Config) to externalize configuration.
*   **Asynchronous Operations:**  Use asynchronous operations (e.g., with `@Async` or message queues) for long-running tasks like sending emails.

This architecture provides a solid foundation for building the Motokurye Delivery System's user registration, login, and authentication features.  Remember to adapt it to your specific needs and constraints.  Good luck!
