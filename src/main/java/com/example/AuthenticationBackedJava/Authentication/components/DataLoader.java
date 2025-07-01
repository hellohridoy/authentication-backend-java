package com.example.AuthenticationBackedJava.Authentication.components;

import com.example.AuthenticationBackedJava.Authentication.entity.User;
import com.example.AuthenticationBackedJava.Authentication.enums.Role;
import com.example.AuthenticationBackedJava.Authentication.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class DataLoader implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(DataLoader.class);

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) throws Exception {
        log.info("Starting data initialization...");

        // Create default admin user if not exists
        createDefaultAdminUser();

        // Create default test users if not exists
        createDefaultTestUsers();

        log.info("Data initialization completed.");
    }

    private void createDefaultAdminUser() {
        String adminUsername = "admin";
        String adminEmail = "admin@example.com";

        if (!userRepository.existsByUsername(adminUsername)) {
            User adminUser = new User();
            adminUser.setUsername(adminUsername);
            adminUser.setEmail(adminEmail);
            adminUser.setPassword(passwordEncoder.encode("admin123"));
            adminUser.setFirstName("System");
            adminUser.setLastName("Administrator");

            // Add roles using enum values
            adminUser.addRole(Role.ADMIN);
            adminUser.addRole(Role.USER);

            // Set account status
            adminUser.setIsEnabled(true);
            adminUser.setIsAccountNonExpired(true);
            adminUser.setIsAccountNonLocked(true);
            adminUser.setIsCredentialsNonExpired(true);

            userRepository.save(adminUser);
            log.info("Default admin user created: {}", adminUsername);
        } else {
            log.info("Admin user already exists: {}", adminUsername);
        }
    }

    private void createDefaultTestUsers() {
        // Create a regular user
        createTestUser("user1", "user1@example.com", "John", "Doe", Role.USER);

        // Create a manager user
        createTestUser("manager1", "manager1@example.com", "Jane", "Smith", Role.MANAGER, Role.USER);

        // Create a moderator user
        createTestUser("moderator1", "moderator1@example.com", "Mike", "Johnson", Role.MODERATOR, Role.USER);
    }

    private void createTestUser(String username, String email, String firstName, String lastName, Role... roles) {
        if (!userRepository.existsByUsername(username)) {
            User user = new User();
            user.setUsername(username);
            user.setEmail(email);
            user.setPassword(passwordEncoder.encode("password123"));
            user.setFirstName(firstName);
            user.setLastName(lastName);

            // Add roles
            for (Role role : roles) {
                user.addRole(role);
            }

            // Set account status
            user.setIsEnabled(true);
            user.setIsAccountNonExpired(true);
            user.setIsAccountNonLocked(true);
            user.setIsCredentialsNonExpired(true);

            userRepository.save(user);
            log.info("Test user created: {} with roles: {}", username, java.util.Arrays.toString(roles));
        } else {
            log.info("User already exists: {}", username);
        }
    }
}
