package com.example.AuthenticationBackedJava.Authentication.dto;

import com.example.AuthenticationBackedJava.Authentication.enums.Role;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserCoreInfoDto {
    private String userName;
    private String email;
    private String firstName;
    private String lastName;
    private String imageUrl;
    private Role role;
}
