package com.example.AuthenticationBackedJava.Authentication.repository;

import com.example.AuthenticationBackedJava.Authentication.entity.User;
import com.example.AuthenticationBackedJava.Authentication.enums.Role;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Set;

/**
 * Repository for Role-related operations
 * Since Role is an enum, this repository provides utility methods
 * for working with roles in the context of users
 */
@Repository
public class RoleRepository {

    /**
     * Get all available roles
     */
    public Set<Role> getAllRoles() {
        return Set.of(Role.values());
    }

    /**
     * Check if a role exists
     */
    public boolean roleExists(Role role) {
        return role != null;
    }

    /**
     * Get role by name
     */
    public Role getRoleByName(String roleName) {
        try {
            return Role.valueOf(roleName.toUpperCase());
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /**
     * Get default user role
     */
    public Role getDefaultUserRole() {
        return Role.USER;
    }

    /**
     * Get all admin roles
     */
    public Set<Role> getAdminRoles() {
        return Set.of(Role.ADMIN, Role.MANAGER);
    }

    /**
     * Check if role is admin role
     */
    public boolean isAdminRole(Role role) {
        return role == Role.ADMIN || role == Role.MANAGER;
    }
}
