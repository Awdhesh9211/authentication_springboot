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

        Cookie cookie = new Cookie("refreshToken", tokens.get("refreshToken"));
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setMaxAge(7 * 24 * 60 * 60);
        response.addCookie(cookie);

        return ResponseEntity.ok(Map.of("accessToken", tokens.get("accessToken")));
    }

    @PostMapping("/auth/refresh")
    public ResponseEntity<Map<String,String>> refresh(@CookieValue(value = "refreshToken", required = false) String token) {

        if (token == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        RefreshToken rt = refreshService.verify(token); // throws if invalid

        String newAccessToken = jwtService.generateToken(rt.getUser(), 10);
        return ResponseEntity.ok(Map.of("accessToken", newAccessToken));
    }


    @PostMapping("/auth/logout")
    public ResponseEntity<String> logout(@CookieValue(value = "refreshToken", required = false) String token,
                                         HttpServletResponse response) {

        if (token != null) {
            // Delete token from DB if it exists
            refreshRepo.findByToken(token).ifPresent(refreshRepo::delete);
        }

        // Delete cookie
        Cookie cookie = new Cookie("refreshToken", null);
        cookie.setHttpOnly(true);  // Security: JS cannot read
        cookie.setSecure(false);   // true if HTTPS
        cookie.setPath("/");        // cookie sent to all auth endpoints
        cookie.setMaxAge(0);        // remove cookie
        response.addCookie(cookie);

        return ResponseEntity.ok("Logged out successfully");
    }


    @GetMapping("/profile")
    public String profile(){
        return "Welcome Awdhesh 😎 Secure API";
    }
}

