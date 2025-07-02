package com.example.AuthenticationBackedJava.Authentication.service;

import com.example.AuthenticationBackedJava.Authentication.dto.RegisterRequest;
import com.example.AuthenticationBackedJava.Authentication.dto.UserCoreInfoDto;
import com.example.AuthenticationBackedJava.Authentication.entity.User;
import com.example.AuthenticationBackedJava.Authentication.enums.Role;
import com.example.AuthenticationBackedJava.Authentication.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@Transactional
public class UserService implements UserDetailsService {

    private static final Logger log = LoggerFactory.getLogger(UserService.class);

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));

        return buildUserDetails(user);
    }

    public UserDetails loadUserByEmail(String email) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(email)
            .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + email));

        return buildUserDetails(user);
    }

    private UserDetails buildUserDetails(User user) {
        Set<GrantedAuthority> authorities = user.getRoles().stream()
            .map(role -> new SimpleGrantedAuthority("ROLE_" + role.name()))
            .collect(Collectors.toSet());

        return org.springframework.security.core.userdetails.User.builder()
            .username(user.getUsername())
            .password(user.getPassword())
            .authorities(authorities)
            .accountExpired(!user.getIsAccountNonExpired())
            .accountLocked(!user.getIsAccountNonLocked())
            .credentialsExpired(!user.getIsCredentialsNonExpired())
            .disabled(!user.getIsEnabled())
            .build();
    }

    public User createUser(RegisterRequest registerRequest) {
        log.info("Creating new user with username: {}", registerRequest.getUsername());

        // Check if user already exists
        if (existsByUsername(registerRequest.getUsername())) {
            throw new RuntimeException("Username already exists: " + registerRequest.getUsername());
        }

        if (existsByEmail(registerRequest.getEmail())) {
            throw new RuntimeException("Email already exists: " + registerRequest.getEmail());
        }

        // Create new user
        User user = new User();
        user.setUsername(registerRequest.getUsername());
        user.setEmail(registerRequest.getEmail());
        user.setPassword(passwordEncoder.encode(registerRequest.getPassword()));
        user.setFirstName(registerRequest.getFirstName());
        user.setLastName(registerRequest.getLastName());

        // Set default role
        user.addRole(Role.USER);

        // Set default account status
        user.setIsEnabled(true);
        user.setIsAccountNonExpired(true);
        user.setIsAccountNonLocked(true);
        user.setIsCredentialsNonExpired(true);

        User savedUser = userRepository.save(user);
        log.info("User created successfully with ID: {}", savedUser.getId());

        return savedUser;
    }

    public User findByUsername(String username) {
        return userRepository.findByUsername(username)
            .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));
    }

    public User findByEmail(String email) {
        return userRepository.findByEmail(email)
            .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + email));
    }

    public Optional<User> findByUsernameOptional(String username) {
        return userRepository.findByUsername(username);
    }

    public Optional<User> findByEmailOptional(String email) {
        return userRepository.findByEmail(email);
    }

    public User findById(Long id) {
        return userRepository.findById(id)
            .orElseThrow(() -> new RuntimeException("User not found with ID: " + id));
    }

    public Optional<User> findByIdOptional(Long id) {
        return userRepository.findById(id);
    }

    public boolean existsByUsername(String username) {
        return userRepository.existsByUsername(username);
    }

    public boolean existsByEmail(String email) {
        return userRepository.existsByEmail(email);
    }

    public User updateUser(Long userId, RegisterRequest updateRequest) {
        User user = findById(userId);

        // Update user details
        if (updateRequest.getUsername() != null && !updateRequest.getUsername().equals(user.getUsername())) {
            if (existsByUsername(updateRequest.getUsername())) {
                throw new RuntimeException("Username already exists: " + updateRequest.getUsername());
            }
            user.setUsername(updateRequest.getUsername());
        }

        if (updateRequest.getEmail() != null && !updateRequest.getEmail().equals(user.getEmail())) {
            if (existsByEmail(updateRequest.getEmail())) {
                throw new RuntimeException("Email already exists: " + updateRequest.getEmail());
            }
            user.setEmail(updateRequest.getEmail());
        }

        if (updateRequest.getFirstName() != null) {
            user.setFirstName(updateRequest.getFirstName());
        }

        if (updateRequest.getLastName() != null) {
            user.setLastName(updateRequest.getLastName());
        }

        if (updateRequest.getPassword() != null && !updateRequest.getPassword().isEmpty()) {
            user.setPassword(passwordEncoder.encode(updateRequest.getPassword()));
        }

        return userRepository.save(user);
    }

    public User updateUserCoreInfo(Long userId, UserCoreInfoDto dto) {
        User user = findById(userId); // Throws exception if user not found

        if (dto.getUserName() != null && !dto.getUserName().equals(user.getUsername())) {
            if (existsByUsername(dto.getUserName())) {
                throw new RuntimeException("Username already exists: " + dto.getUserName());
            }
            user.setUsername(dto.getUserName());
        }

        if (dto.getEmail() != null && !dto.getEmail().equals(user.getEmail())) {
            if (existsByEmail(dto.getEmail())) {
                throw new RuntimeException("Email already exists: " + dto.getEmail());
            }
            user.setEmail(dto.getEmail());
        }

        if (dto.getFirstName() != null) {
            user.setFirstName(dto.getFirstName());
        }

        if (dto.getLastName() != null) {
            user.setLastName(dto.getLastName());
        }

        if (dto.getImageUrl() != null) {
            user.setImageUrl(dto.getImageUrl());
        }

        if (dto.getRole() != null && !user.getRoles().contains(dto.getRole())) {
            user.getRoles().clear(); // Optional: If you want only 1 role
            user.addRole(dto.getRole());
        }

        return userRepository.save(user);
    }

    public List<UserCoreInfoDto> getAllUserCoreInfo() {
        return userRepository.findAll().stream()
            .map(this::mapToCoreInfoDto)
            .toList();
    }

    private UserCoreInfoDto mapToCoreInfoDto(User user) {
        return new UserCoreInfoDto(
            user.getUsername(),
            user.getEmail(),
            user.getFirstName(),
            user.getLastName(),
            user.getImageUrl(), // Assuming `image` is the field name
            user.getRoles().stream().findFirst().orElse(null) // assuming single-role user
        );
    }


    public User addRoleToUser(Long userId, Role role) {
        User user = findById(userId);
        user.addRole(role);
        return userRepository.save(user);
    }

    public User removeRoleFromUser(Long userId, Role role) {
        User user = findById(userId);
        user.removeRole(role);
        return userRepository.save(user);
    }

    public User enableUser(Long userId) {
        User user = findById(userId);
        user.setIsEnabled(true);
        return userRepository.save(user);
    }

    public User disableUser(Long userId) {
        User user = findById(userId);
        user.setIsEnabled(false);
        return userRepository.save(user);
    }

    public User lockUser(Long userId) {
        User user = findById(userId);
        user.setIsAccountNonLocked(false);
        return userRepository.save(user);
    }

    public User unlockUser(Long userId) {
        User user = findById(userId);
        user.setIsAccountNonLocked(true);
        return userRepository.save(user);
    }

    public List<User> findAllUsers() {
        return userRepository.findAll();
    }

    public List<User> findUsersByRole(Role role) {
        return userRepository.findByRolesContaining(role);
    }

    public List<User> findEnabledUsers() {
        return userRepository.findByIsEnabledTrue();
    }

    public List<User> findDisabledUsers() {
        return userRepository.findByIsEnabledFalse();
    }

    public void deleteUser(Long userId) {
        User user = findById(userId);
        userRepository.delete(user);
        log.info("User deleted successfully: {}", user.getUsername());
    }

    public boolean changePassword(String username, String oldPassword, String newPassword) {
        User user = findByUsername(username);

        // Verify old password
        if (!passwordEncoder.matches(oldPassword, user.getPassword())) {
            return false;
        }

        // Update password
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        log.info("Password changed successfully for user: {}", username);
        return true;
    }

    public void resetPassword(String email, String newPassword) {
        User user = findByEmail(email);
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
        log.info("Password reset successfully for user: {}", user.getUsername());
    }

    public long countUsers() {
        return userRepository.count();
    }

    public long countEnabledUsers() {
        return userRepository.countByIsEnabledTrue();
    }

    public long countUsersByRole(Role role) {
        return userRepository.countByRolesContaining(role);
    }
}
