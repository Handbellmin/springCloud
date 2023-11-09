package com.example.userservice.security.auth;

import com.example.userservice.jpa.UserRepository;
import com.example.userservice.jpa.Users;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;


@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Users users = userRepository.findByEmail(username);
        if (users != null) {
            return new PrincipalDetails(users);
        }else {
            throw new UsernameNotFoundException(username);
        }
    }
}
