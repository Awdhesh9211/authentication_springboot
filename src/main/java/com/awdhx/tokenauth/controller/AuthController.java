package com.awdhx.tokenauth.controller;

import com.awdhx.tokenauth.entity.RefreshToken;
import com.awdhx.tokenauth.entity.User;
import com.awdhx.tokenauth.repository.RefreshTokenRepo;
import com.awdhx.tokenauth.repository.UserRepo;
import com.awdhx.tokenauth.service.AuthService;
import com.awdhx.tokenauth.service.JwtService;
import com.awdhx.tokenauth.service.RefreshTokenService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    AuthService authService;
    @Autowired
    RefreshTokenService refreshService;
    @Autowired
    JwtService jwtService;
    @Autowired
    RefreshTokenRepo refreshRepo;
    @Autowired
    UserRepo userRepo;
    @Autowired
    PasswordEncoder encoder;

    @PostMapping("/register")
    public String register(@RequestBody User user){
        user.setPassword(encoder.encode(user.getPassword()));
        userRepo.save(user);
        return "User Registered";
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String,String> req, HttpServletResponse response){

        Map<String,String> tokens = authService.login(req.get("username"), req.get("password"));

        Cookie cookie = new Cookie("refreshToken", tokens.get("refreshToken"));
        cookie.setHttpOnly(true);
        cookie.setPath("/auth/refresh");
        cookie.setMaxAge(7 * 24 * 60 * 60);
        response.addCookie(cookie);

        return ResponseEntity.ok(Map.of("accessToken", tokens.get("accessToken")));
    }

    @PostMapping("/refresh")
    public Map<String,String> refresh(@CookieValue("refreshToken") String token){
        RefreshToken rt = refreshService.verify(token);
        return Map.of("accessToken", jwtService.generateToken(rt.getUser(), 10));
    }

    @PostMapping("/logout")
    public String logout(@CookieValue("refreshToken") String token, HttpServletResponse response){
        refreshRepo.deleteByToken(token);
        Cookie cookie = new Cookie("refreshToken", null);
        cookie.setMaxAge(0);
        cookie.setPath("/auth/refresh");
        response.addCookie(cookie);
        return "Logged out";
    }

    @GetMapping("/profile")
    public String profile(){
        return "Welcome Awdhesh 😎 Secure API";
    }
}

