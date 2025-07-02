package com.example.AuthenticationBackedJava.Authentication.controller;

import com.example.AuthenticationBackedJava.Authentication.dto.UserCoreInfoDto;
import com.example.AuthenticationBackedJava.Authentication.entity.User;
import com.example.AuthenticationBackedJava.Authentication.repository.UserRepository;
import com.example.AuthenticationBackedJava.Authentication.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/users")
public class UserRestController {

    private final UserService userService;
    private final UserRepository userRepository;

    // Get all users (as DTO)
    @GetMapping("/user-core-info")
    public List<UserCoreInfoDto> getAllUserCoreInfo() {
        return userService.getAllUserCoreInfo();
    }

    // Update a user's core info
    @PutMapping("/user-core-info/{id}")
    public UserCoreInfoDto updateUserCoreInfo(@PathVariable Long id, @RequestBody @Valid UserCoreInfoDto dto) {
        User updatedUser = userService.updateUserCoreInfo(id, dto);
        return new UserCoreInfoDto(
            updatedUser.getUsername(),
            updatedUser.getEmail(),
            updatedUser.getFirstName(),
            updatedUser.getLastName(),
            updatedUser.getImageUrl(),
            updatedUser.getRoles().stream().findFirst().orElse(null)
        );
    }

    // Delete user
    @DeleteMapping("/user-core-info/{id}")
    public ResponseEntity<String> deleteUser(@PathVariable Long id) {
        userRepository.deleteById(id);
        return ResponseEntity.ok("User deleted successfully with ID: " + id);
    }
}
