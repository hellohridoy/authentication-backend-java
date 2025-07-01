package com.example.AuthenticationBackedJava.Authentication.service;

import com.example.AuthenticationBackedJava.Authentication.entity.User;
import com.example.AuthenticationBackedJava.Authentication.repository.UserRepository;
import com.example.AuthenticationBackedJava.Authentication.util.UserPrincipal;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(email)
            .orElseThrow(() ->
                new UsernameNotFoundException("User not found with email: " + email)
            );

        return UserPrincipal.create(user);
    }

    // This method is used by JWTAuthenticationFilter
    @Transactional
    public UserDetails loadUserById(Long id) {
        User user = userRepository.findById(id)
            .orElseThrow(() ->
                new UsernameNotFoundException("User not found with id: " + id)
            );

        return UserPrincipal.create(user);
    }
}
