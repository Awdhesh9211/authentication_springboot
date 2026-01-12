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
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
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

    @PostMapping("/auth/register")
    public String register(@RequestBody User user){
        user.setPassword(encoder.encode(user.getPassword()));
        userRepo.save(user);
        return "User Registered";
    }

    @PostMapping("/auth/login")
    public ResponseEntity<?> login(@RequestBody Map<String,String> req, HttpServletResponse response){

        Map<String,String> tokens = authService.login(req.get("username"), req.get("password"));

        // Refresh Token
        Cookie refreshCookie = new Cookie("refreshToken", tokens.get("refreshToken"));
        refreshCookie.setHttpOnly(true);
        refreshCookie.setPath("/");
        refreshCookie.setMaxAge(30 * 24 * 60 * 60);
        response.addCookie(refreshCookie);

        // Access Token
        Cookie accessCookie = new Cookie("accessToken", tokens.get("accessToken"));
        accessCookie.setHttpOnly(true);
        accessCookie.setPath("/");
        accessCookie.setMaxAge(10 * 60); // 10 minutes
        response.addCookie(accessCookie);   // ✅ THIS WAS MISSING

        return ResponseEntity.ok("Login Success !");
    }


    @PostMapping("/auth/refresh")
    public ResponseEntity<?> refresh(
            @CookieValue(value = "refreshToken", required = false) String token,
            HttpServletResponse response) {

        if (token == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        RefreshToken rt = refreshService.verify(token);

        String newAccessToken = jwtService.generateToken(rt.getUser(), 10);

        Cookie accessCookie = new Cookie("accessToken", newAccessToken);
        accessCookie.setHttpOnly(true);
        accessCookie.setPath("/");
        accessCookie.setMaxAge(10 * 60);
        response.addCookie(accessCookie);

        return ResponseEntity.ok("Access token refreshed");
    }



    @PostMapping("/auth/logout")
    public ResponseEntity<String> logout(
            @CookieValue(value = "refreshToken", required = false) String token,
            HttpServletResponse response) {

        if (token != null) {
            refreshRepo.findByToken(token).ifPresent(refreshRepo::delete);
        }

        Cookie refresh = new Cookie("refreshToken", null);
        refresh.setHttpOnly(true);
        refresh.setPath("/");
        refresh.setMaxAge(0);

        Cookie access = new Cookie("accessToken", null);
        access.setHttpOnly(true);
        access.setPath("/");
        access.setMaxAge(0);

        response.addCookie(refresh);
        response.addCookie(access);

        return ResponseEntity.ok("Logged out successfully");
    }



    @GetMapping("/user/profile")
    public String profile(){
        return "Welcome Awdhesh 😎 Secure API";
    }

    @GetMapping("/admin/create")
    public String create(){
        return "Admin Page ";
    }
}

