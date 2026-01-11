package com.awdhx.tokenauth.service;

import com.awdhx.tokenauth.entity.User;
import com.awdhx.tokenauth.repository.UserRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class AuthService {

    @Autowired
    UserRepo userRepo;
    @Autowired RefreshTokenService refreshService;
    @Autowired JwtService jwt;
    @Autowired
    PasswordEncoder encoder;

    public Map<String,String> login(String username, String password) {
        User user = userRepo.findByUsername(username).orElseThrow();

        if(!encoder.matches(password, user.getPassword()))
            throw new RuntimeException("Invalid credentials");

        String accessToken = jwt.generateToken(user, 10);
        String refreshToken = refreshService.create(user).getToken();

        return Map.of("accessToken", accessToken, "refreshToken", refreshToken);
    }
}
