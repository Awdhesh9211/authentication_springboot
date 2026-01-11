package com.awdhx.tokenauth.security;

import com.awdhx.tokenauth.entity.RefreshToken;
import com.awdhx.tokenauth.entity.User;
import com.awdhx.tokenauth.repository.RefreshTokenRepo;
import com.awdhx.tokenauth.repository.UserRepo;
import com.awdhx.tokenauth.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

@Component
public class JwtFilter extends OncePerRequestFilter {

    @Autowired
    private JwtService jwt;

    @Autowired
    private UserRepo userRepo;

    @Autowired
    private RefreshTokenRepo refreshRepo;

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res,
                                    FilterChain chain) throws IOException, ServletException {

        String header = req.getHeader("Authorization");
        String username = null;

        // 1️⃣ Check Authorization header first
        if (header != null && header.startsWith("Bearer ")) {
            String token = header.substring(7);
            username = jwt.extractUsername(token);

        } else {
            // 2️⃣ If no header, check cookie
            if (req.getCookies() != null) {
                for (Cookie cookie : req.getCookies()) {
                    if (cookie.getName().equals("refreshToken")) {
                        String refreshToken = cookie.getValue();
                        Optional<RefreshToken> rtOpt = refreshRepo.findByToken(refreshToken);
                        if (rtOpt.isPresent() && rtOpt.get().getExpiryDate().isAfter(java.time.Instant.now())) {
                            username = rtOpt.get().getUser().getUsername();
                        }
                        break;
                    }
                }
            }
        }

        // 3️⃣ If username found, set authentication
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            User user = userRepo.findByUsername(username).orElseThrow();

            UsernamePasswordAuthenticationToken auth =
                    new UsernamePasswordAuthenticationToken(user, null, List.of());

            SecurityContextHolder.getContext().setAuthentication(auth);
        }

        chain.doFilter(req, res);
    }
}
