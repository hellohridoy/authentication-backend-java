package com.example.AuthenticationBackedJava.Authentication.repository;

import com.example.AuthenticationBackedJava.Authentication.entity.User;
import com.example.AuthenticationBackedJava.Authentication.enums.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    // Find user by username
    Optional<User> findByUsername(String username);

    // Find user by email
    Optional<User> findByEmail(String email);

    // Check if username exists
    boolean existsByUsername(String username);

    // Check if email exists
    boolean existsByEmail(String email);

    // Find users by role
    List<User> findByRolesContaining(Role role);

    // Find enabled users
    List<User> findByIsEnabledTrue();

    // Find disabled users
    List<User> findByIsEnabledFalse();

    // Find locked users
    List<User> findByIsAccountNonLockedFalse();

    // Find unlocked users
    List<User> findByIsAccountNonLockedTrue();

    // Count enabled users
    long countByIsEnabledTrue();

    // Count disabled users
    long countByIsEnabledFalse();

    // Count users by role
    long countByRolesContaining(Role role);

    // Find users by first name
    List<User> findByFirstNameContainingIgnoreCase(String firstName);

    // Find users by last name
    List<User> findByLastNameContainingIgnoreCase(String lastName);

    // Find users by full name
    @Query("SELECT u FROM User u WHERE " +
        "LOWER(CONCAT(u.firstName, ' ', u.lastName)) LIKE LOWER(CONCAT('%', :fullName, '%'))")
    List<User> findByFullNameContainingIgnoreCase(@Param("fullName") String fullName);

    // Find users by email domain
    @Query("SELECT u FROM User u WHERE u.email LIKE CONCAT('%@', :domain)")
    List<User> findByEmailDomain(@Param("domain") String domain);

    // Find recently created users - Fixed query
    @Query("SELECT u FROM User u WHERE u.createdAt >= :cutoffDate")
    List<User> findRecentlyCreatedUsers(@Param("cutoffDate") LocalDateTime cutoffDate);

    // Custom query to find users with multiple roles
    @Query("SELECT u FROM User u WHERE SIZE(u.roles) > 1")
    List<User> findUsersWithMultipleRoles();

    // Find users by username or email
    @Query("SELECT u FROM User u WHERE u.username = :identifier OR u.email = :identifier")
    Optional<User> findByUsernameOrEmail(@Param("identifier") String identifier);
}
