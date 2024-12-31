package com.todo.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.todo.model.User;
import com.todo.repository.UserRepository;
import com.todo.util.JwtUtil;

@Service
public class AuthService {
    private static final Logger log = LoggerFactory.getLogger(AuthService.class);
    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;
    private final BCryptPasswordEncoder passwordEncoder;

    @Autowired
    public AuthService(UserRepository userRepository, JwtUtil jwtUtil,BCryptPasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.jwtUtil = jwtUtil;
        this.passwordEncoder = passwordEncoder;
    }

    public String registerUser(String username, String password) {
        if (userRepository.findByUsername(username).isPresent()) {
            throw new RuntimeException("User already exists");
        }
        if (username.isBlank() || password.isBlank()) {
            throw new RuntimeException("Username and password cannot be empty");
        }
        User user = new User();
        user.setUsername(username);
        user.setPassword(password); // In production, hash the password with BCrypt or similar
        userRepository.save(user);
        return "User registered successfully";
    }

    public String loginUser(String username, String password) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Invalid credentials"));
        if (user == null || !passwordEncoder.matches(password, user.getPassword())) {
            throw new RuntimeException("Invalid credentials");
        }
        String token=jwtUtil.generateToken(username);
        log.info("Generated token: {}, username: {}", token, username);
        return token;
    }



    public String validateToken(String token) {
        String username = jwtUtil.extractUsername(token);
        if (userRepository.findByUsername(username).isEmpty() || !jwtUtil.validateToken(token, username)) {
            throw new RuntimeException("Invalid token");
        }
        return username;
    }
}
