package com.example.AuthenticationBackedJava.Authentication.service;

import com.example.AuthenticationBackedJava.Authentication.entity.User;
import com.example.AuthenticationBackedJava.Authentication.repository.UserRepository;
import com.example.AuthenticationBackedJava.Authentication.util.UserPrincipal;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(email)
            .orElseThrow(() ->
                new UsernameNotFoundException("User not found with email: " + email)
            );

        return UserPrincipal.create(user);
    }

}
