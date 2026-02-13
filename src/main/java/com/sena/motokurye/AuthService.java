Okay, let's start implementing the code based on the architecture and details provided.  I'll provide the code in chunks, along with commit messages and explanations.

**1. `pom.xml`**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>3.2.0</version>
        <relativePath/> <!-- lookup parent from repository -->
    </parent>
    <groupId>com.motokurye</groupId>
    <artifactId>delivery</artifactId>
    <version>0.0.1-SNAPSHOT</version>
    <name>delivery</name>
    <description>Motokurye Delivery System</description>
    <properties>
        <java.version>17</java.version>
    </properties>
    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-jpa</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
        <dependency>
            <groupId>org.postgresql</groupId>
            <artifactId>postgresql</artifactId>
            <scope>runtime</scope>
        </dependency>
        <dependency>
            <groupId>org.projectlombok</groupId>
            <artifactId>lombok</artifactId>
            <optional>true</optional>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-test</artifactId>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt-api</artifactId>
            <version>0.12.3</version>
        </dependency>
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt-impl</artifactId>
            <version>0.12.3</version>
            <scope>runtime</scope>
        </dependency>
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt-jackson</artifactId>
            <version>0.12.3</version>
            <scope>runtime</scope>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-validation</artifactId>
        </dependency>
        <dependency>
            <groupId>org.flywaydb</groupId>
            <artifactId>flyway-core</artifactId>
        </dependency>
        <dependency>
            <groupId>org.flywaydb</groupId>
            <artifactId>flyway-maven-plugin</artifactId>
            <version>9.22.0</version>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
                <configuration>
                    <excludes>
                        <exclude>
                            <groupId>org.projectlombok</groupId>
                            <artifactId>lombok</artifactId>
                        </exclude>
                    </excludes>
                </configuration>
            </plugin>
            <plugin>
                <groupId>org.flywaydb</groupId>
                <artifactId>flyway-maven-plugin</artifactId>
                <configuration>
                    <url>jdbc:postgresql://localhost:5432/motokurye</url>
                    <user>postgres</user>
                    <password>admin</password>
                    <schemas>public</schemas>
                    <table>flyway_schema_history</table>
                </configuration>
                <dependencies>
                    <dependency>
                        <groupId>org.postgresql</groupId>
                        <artifactId>postgresql</artifactId>
                        <version>${postgresql.version}</version>
                    </dependency>
                </dependencies>
            </plugin>
        </plugins>
    </build>

</project>
```

**Commit Message:** `feat: initial pom.xml with necessary dependencies`

**Explanation:**

*   Includes Spring Boot starters for Data JPA, Web, Security, Validation.
*   Adds PostgreSQL driver.
*   Includes Lombok for boilerplate code reduction.
*   Adds JWT dependencies (`jjwt-api`, `jjwt-impl`, `jjwt-jackson`).
*   Includes Flyway for database migrations.
*   Sets up the Flyway plugin with database credentials.  **Important:** Replace the database credentials with your actual PostgreSQL credentials.  It's best to use a dedicated development database.  Also, these credentials should ideally be in application.properties and accessed as variables instead of hardcoded here, but I have done this for brevity.

**2. `src/main/resources/application.properties`**

```properties
spring.application.name=motokurye-delivery-system
spring.datasource.url=jdbc:postgresql://localhost:5432/motokurye
spring.datasource.username=postgres
spring.datasource.password=admin
spring.jpa.hibernate.ddl-auto=none
spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.PostgreSQLDialect
spring.flyway.enabled=true
jwt.secret=your-secret-key  # Replace with a strong, randomly generated secret
jwt.expiration=900000 # 15 minutes in milliseconds
```

**Commit Message:** `feat: add application.properties with database and JWT configurations`

**Explanation:**

*   Configures the database connection (URL, username, password). **Important:** Replace the database credentials with your actual PostgreSQL credentials.
*   Sets `spring.jpa.hibernate.ddl-auto=none` to prevent Hibernate from automatically creating or updating the schema.  Flyway will manage the schema.
*   Enables Flyway migrations.
*   Defines `jwt.secret` and `jwt.expiration` properties.  **Critical:** Replace `your-secret-key` with a strong, randomly generated secret. This should be stored securely in a production environment (e.g., using environment variables or a secrets management system).  The expiration time is set to 15 minutes.

**3. `src/main/resources/db/migration/V1__create_users_table.sql`**

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
```

**Commit Message:** `feat: add Flyway migration script for creating the users table`

**Explanation:**

*   Creates the `user_role` enum.
*   Creates the `users` table with the specified columns and constraints.
*   Adds indexes to `email`, `phone_number`, and `role` for faster queries.
*   Ensures that either email or phone_number is present, but not both null.

**4. `src/main/java/com/motokurye/delivery/entity/User.java`**

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

**Commit Message:** `feat: add User entity`

**Explanation:**

*   Defines the `User` entity with JPA annotations.
*   Uses Lombok's `@Data` annotation to generate getters, setters, `equals`, `hashCode`, and `toString` methods.
*   Maps the `role` field to the `user_role` enum in the database.
*   Uses `@CreationTimestamp` and `@UpdateTimestamp` to automatically manage the `createdAt` and `updatedAt` fields.

**5. `src/main/java/com/motokurye/delivery/enums/Role.java`**

```java
package com.motokurye.delivery.enums;

public enum Role {
    customer,
    courier,
    admin
}
```

**Commit Message:** `feat: add Role enum`

**Explanation:**

*   Defines the `Role` enum with the possible user roles.

**6. `src/main/java/com/motokurye/delivery/repository/UserRepository.java`**

```java
package com.motokurye.delivery.repository;

import com.motokurye.delivery.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmail(String email);

    Optional<User> findByPhoneNumber(String phoneNumber);

    boolean existsByEmail(String email);

    boolean existsByPhoneNumber(String phoneNumber);
}
```

**Commit Message:** `feat: add UserRepository`

**Explanation:**

*   Defines the `UserRepository` interface, which extends `JpaRepository`.
*   Provides methods for finding users by email or phone number, and checking if a user exists by email or phone number.

**7. `src/main/java/com/motokurye/delivery/dto/RegisterRequest.java`**

```java
package com.motokurye.delivery.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class RegisterRequest {

    private String email;

    private String phoneNumber;

    @NotBlank(message = "Password is required")
    @Size(min = 8, message = "Password must be at least 8 characters long")
    private String password;

    @NotBlank(message = "Role is required")
    private String role;

    private String licensePlate;
}
```

**Commit Message:** `feat: add RegisterRequest DTO with validation annotations`

**Explanation:**

*   Defines the `RegisterRequest` DTO with fields for user registration data.
*   Uses `javax.validation` annotations for input validation:
    *   `@Email`: Validates the email format.
    *   `@NotBlank`: Ensures that the field is not null or empty.
    *   `@Size`: Validates the length of the password.
    *   `@Pattern`: (Not used here, but can be used for phone number or license plate validation).

**8. `src/main/java/com/motokurye/delivery/dto/LoginRequest.java`**

```java
package com.motokurye.delivery.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class LoginRequest {

    private String email;
    private String phoneNumber;

    @NotBlank(message = "Password is required")
    private String password;
}
```

**Commit Message:** `feat: add LoginRequest DTO`

**Explanation:**

*   Defines the `LoginRequest` DTO with fields for user login data.
*   Uses `@NotBlank` annotation to ensure password is not blank.

**9. `src/main/java/com/motokurye/delivery/dto/AuthenticationResponse.java`**

```java
package com.motokurye.delivery.dto;

import lombok.Data;

@Data
public class AuthenticationResponse {
    private String token;
}
```

**Commit Message:** `feat: add AuthenticationResponse DTO`

**Explanation:**

*   Defines the `AuthenticationResponse` DTO with a field for the JWT token.

**10. `src/main/java/com/motokurye/delivery/dto/UserDTO.java`**

```java
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

**Commit Message:** `feat: add UserDTO`

**Explanation:**

*   Defines the `UserDTO` for transferring user information without sensitive data.

**11. `src/main/java/com/motokurye/delivery/exception/UserAlreadyExistsException.java`**

```java
package com.motokurye.delivery.exception;

public class UserAlreadyExistsException extends RuntimeException {

    public UserAlreadyExistsException(String message) {
        super(message);
    }
}
```

**Commit Message:** `feat: add UserAlreadyExistsException`

**Explanation:**

*   Defines a custom exception for when a user with the same email or phone number already exists.

**12. `src/main/java/com/motokurye/delivery/exception/InvalidCredentialsException.java`**

```java
package com.motokurye.delivery.exception;

public class InvalidCredentialsException extends RuntimeException {

    public InvalidCredentialsException(String message) {
        super(message);
    }
}
```

**Commit Message:** `feat: add InvalidCredentialsException`

**Explanation:**

*   Defines a custom exception for invalid login credentials.

**13. `src/main/java/com/motokurye/delivery/controller/AuthenticationController.java`**

```java
package com.motokurye.delivery.controller;

import com.motokurye.delivery.dto.RegisterRequest;
import com.motokurye.delivery.dto.LoginRequest;
import com.motokurye.delivery.dto.AuthenticationResponse;
import com.motokurye.delivery.dto.UserDTO;
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

**Commit Message:** `feat: add AuthenticationController`

**Explanation:**

*   Defines the `AuthenticationController` with `/register` and `/login` endpoints.
*   Injects the `AuthenticationService`.
*   Uses `@Valid` to validate the `RegisterRequest` DTO.
*   Handles exceptions and returns appropriate error responses.

**14. `src/main/java/com/motokurye/delivery/service/AuthenticationService.java`**

```java
package com.motokurye.delivery.service;

import com.motokurye.delivery.dto.RegisterRequest;
import com.motokurye.delivery.dto.LoginRequest;
import com.motokurye.delivery.dto.AuthenticationResponse;
import com.motokurye.delivery.dto.UserDTO;
import com.motokurye.delivery.entity.User;
import com.motokurye.delivery.enums.Role;
import com.motokurye.delivery.exception.InvalidCredentialsException;
import com.motokurye.delivery.exception.UserAlreadyExistsException;
import com.motokurye.delivery.repository.UserRepository;
import jakarta.transaction.Transactional;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthenticationService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    public AuthenticationService(UserRepository userRepository, BCryptPasswordEncoder passwordEncoder, JwtService jwtService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
    }

    @Transactional
    public UserDTO register(RegisterRequest registerRequest) {
        if (registerRequest.getEmail() != null && userRepository.existsByEmail(registerRequest.getEmail())) {
            throw new UserAlreadyExistsException("Email already exists");
        }
        if (registerRequest.getPhoneNumber() != null && userRepository.existsByPhoneNumber(registerRequest.getPhoneNumber())) {
            throw new UserAlreadyExistsException("Phone number already exists");
        }

        User user = new User();

        if (registerRequest.getEmail() != null) {
            user.setEmail(registerRequest.getEmail());
        } else if (registerRequest.getPhoneNumber() != null) {
            user.setPhoneNumber(registerRequest.getPhoneNumber());
        } else {
            throw new IllegalArgumentException("Either email or phone number must be provided");
        }


        user.setPasswordHash(passwordEncoder.encode(registerRequest.getPassword()));

        try {
            user.setRole(Role.valueOf(registerRequest.getRole()));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid role: " + registerRequest.getRole());
        }

        user.setLicensePlate(registerRequest.getLicensePlate());

        User savedUser = userRepository.save(user);

        return convertToDto(savedUser);
    }

    public AuthenticationResponse login(LoginRequest loginRequest) {
        User user = null;
        if (loginRequest.getEmail() != null) {
            user = userRepository.findByEmail(loginRequest.getEmail()).orElse(null);
        } else if (loginRequest.getPhoneNumber() != null) {
            user = userRepository.findByPhoneNumber(loginRequest.getPhoneNumber()).orElse(null);
        }

        if (user == null || !passwordEncoder.matches(loginRequest.getPassword(), user.getPasswordHash())) {
            throw new InvalidCredentialsException("Invalid credentials");
        }

        String jwtToken = jwtService.generateToken(user);
        return new AuthenticationResponse(jwtToken);
    }

    private UserDTO convertToDto(User user) {
        UserDTO dto = new UserDTO();
        dto.setId(user.getId());
        dto.setEmail(user.getEmail());
        dto.setPhoneNumber(user.getPhoneNumber());
        dto.setRole(user.getRole().toString());
        dto.setLicensePlate(user.getLicensePlate());
        return dto;
    }
}
```

**Commit Message:** `feat: add AuthenticationService with registration and login logic`

**Explanation:**

*   Injects `UserRepository`, `BCryptPasswordEncoder`, and `JwtService`.
*   `register()`:
    *   Checks if a user with the same email or phone number already exists.
    *   Hashes the password using `BCryptPasswordEncoder`.
    *   Saves the user to the database.
    *   Converts the saved `User` entity to a `UserDTO`.
*   `login()`:
    *   Retrieves the user from the database based on the provided email or phone number.
    *   Verifies the password using `BCryptPasswordEncoder`.
    *   Generates a JWT token using `JwtService`.
    *   Returns an `AuthenticationResponse` containing the JWT token.
*   Includes a `convertToDto` method to convert User entity to UserDto
*   The `@Transactional` annotation ensures that the whole registration is atomic.

**15. `src/main/java/com/motokurye/delivery/service/JwtService.java`**

```java
package com.motokurye.delivery.service;

import com.motokurye.delivery.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
public class JwtService {

    @Value("${jwt.secret}")
    private String secretKey;

    @Value("${jwt.expiration}")
    private long jwtExpiration;

    public String generateToken(User user) {
        return generateToken(new HashMap<>(), user);
    }

    public String generateToken(Map<String, Object> extraClaims, User user) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(user.getId().toString())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + jwtExpiration))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String extractUserId(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, java.util.function.Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
```

**Commit Message:** `feat: add JwtService for JWT generation and validation`

**Explanation:**

*   Reads the JWT secret key and expiration time from the application properties.
*   `generateToken()`: Generates a JWT token for the given user.  The token includes the user ID as the subject.
*   `extractUserId()`: Extracts the user ID from the JWT token.
*   `extractClaim()`: A generic method for extracting claims from the JWT token.
*   `extractAllClaims()`: Extracts all claims from the JWT token.
*   `getSignInKey()`: Returns the signing key used to sign the JWT.

**16. `src/main/java/com/motokurye/delivery/MotokuryeDeliverySystemApplication.java`**

```java
package com.motokurye.delivery;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootApplication
public class MotokuryeDeliverySystemApplication {

    public static void main(String[] args) {
        SpringApplication.run(MotokuryeDeliverySystemApplication.class, args);
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

**Commit Message:** `feat: add main application class and BCryptPasswordEncoder bean`

**Explanation:**

*   The main application class.
*   Creates a `BCryptPasswordEncoder` bean, making it available for dependency injection.

**17. `src/main/java/com/motokurye/delivery/config/SecurityConfig.java`**

```java
package com.motokurye.delivery.config;

import com.motokurye.delivery.filter.JwtAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;

    public SecurityConfig(JwtAuthenticationFilter jwtAuthFilter, AuthenticationProvider authenticationProvider) {
        this.jwtAuthFilter = jwtAuthFilter;
        this.authenticationProvider = authenticationProvider;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/**").permitAll()
                        .anyRequest().authenticated()
                )
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
```

**Commit Message:** `feat: add SecurityConfig for Spring Security configuration`

**Explanation:**

*   Disables CSRF protection (for simplicity, but consider enabling it in production with proper configuration).
*   Configures authorization rules:
    *   Permits all requests to `/api/auth/**` (registration and login endpoints).
    *   Requires authentication for all other requests.
*   Configures session management to be stateless (JWT-based).
*   Adds the `JwtAuthenticationFilter` before the `UsernamePasswordAuthenticationFilter`.

**18.  `src/main/java/com/motokurye/delivery/filter/JwtAuthenticationFilter.java`**

```java
package com.motokurye.delivery.filter;

import com.motokurye.delivery.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    public JwtAuthenticationFilter(JwtService jwtService, UserDetailsService userDetailsService) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        final String jwt;
        final String userId;

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        jwt = authHeader.substring(7); // "Bearer " + token
        userId = jwtService.extractUserId(jwt);

        if (userId != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userId); // Use userId as username

            if (userDetails != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );

                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        filterChain.doFilter(request, response);
    }
}
```

**Commit Message:** `feat: add JwtAuthenticationFilter for JWT validation`

**Explanation:**

*   Extends `OncePerRequestFilter` to ensure the filter is executed only once per request.
*   Extracts the JWT from the `Authorization` header.
*   Extracts the user ID from the JWT.
*   If the user is not already authenticated:
    *   Loads the user details from the `UserDetailsService`.
    *   Creates an `UsernamePasswordAuthenticationToken` and sets it in the `SecurityContextHolder`.
*   Calls `filterChain.doFilter()` to continue the filter chain.

**19. `src/main/java/com/motokurye/delivery/config/ApplicationConfig.java`**

```java
package com.motokurye.delivery.config;

import com.motokurye.delivery.repository.UserRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
public class ApplicationConfig {

    private final UserRepository userRepository;

    public ApplicationConfig(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return userId -> userRepository.findById(Long.parseLong(userId))
                .map(user -> new org.springframework.security.core.userdetails.User(
                        user.getId().toString(),
                        user.getPasswordHash(),
                        true,
                        true,
                        true,
                        true,
                        null  // Authorities will need to be populated later based on user role
                ))
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }


    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(new BCryptPasswordEncoder());
        return authProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}
```

**Commit Message:** `feat: add ApplicationConfig to configure UserDetailsService and AuthenticationProvider`

**Explanation:**

*   Configures a `UserDetailsService` that loads user details from the database based on the user ID.
*   Configures an `AuthenticationProvider` that uses the `UserDetailsService` and `BCryptPasswordEncoder` to authenticate users.
*   Configures the `AuthenticationManager`.
*   Important:  The `UserDetailsService` currently returns a `null` authorities list. You'll need to populate this list based on the user's role to enable role-based authorization.

**20. `src/main/java/com/motokurye/delivery/exception/GlobalExceptionHandler.java`**

```java
package com.motokurye.delivery.exception;

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

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<String> handleIllegalArgumentException(IllegalArgumentException ex) {
        return new ResponseEntity<>(ex.getMessage(), HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<String> handleGeneralException(Exception ex) {
        return new ResponseEntity<>("An unexpected error occurred: " + ex.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
    }
}
```

**Commit Message:** `feat: add GlobalExceptionHandler for handling exceptions`

**Explanation:**

*   Defines a `GlobalExceptionHandler` to handle exceptions globally.
*   Provides