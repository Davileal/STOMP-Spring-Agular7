package com.example.demo.service;

import com.example.demo.security.JwtTokenProvider;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
public class AuthenticationService {

    private Set<String> loggedUsers = new HashSet<>();
    private final JwtTokenProvider jwtTokenProvider;
    private final AuthenticationManager authenticationManager;

    public AuthenticationService(JwtTokenProvider jwtTokenProvider,
                                 AuthenticationManager authenticationManager) {
        this.jwtTokenProvider = jwtTokenProvider;
        this.authenticationManager = authenticationManager;
    }

    public UserLoggedDTO authenticate(AuthenticationDTO authenticationDTO) throws Exception {
        try {
            Authentication authentication = authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(authenticationDTO.username.toLowerCase(),
                            authenticationDTO.password));
            SecurityContextHolder.getContext().setAuthentication(authentication);
            String idToken = jwtTokenProvider.createToken("1");
            UserLoggedDTO dto = new UserLoggedDTO();
            dto.token = idToken;
            dto.name = "Davi";
            return dto;
        } catch (AuthenticationException e) {
            throw new Exception("Login inválido");
        }
    }

    class UserLoggedDTO {
        public String token;
        public String name;
    }

    class AuthenticationDTO {
        public String username;
        public String password;
    }

}
