package com.example.finaluser.service;


import com.example.finaluser.jwt.JWTUtill;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

@Service
public class ReissueService {

    private final JWTUtill jwtUtill;
    public ReissueService(JWTUtill jwtUtill) {
        this.jwtUtill = jwtUtill;
    }
    public ResponseEntity<String> reissue(String refreshToken, HttpServletResponse response) {


        if (refreshToken == null) {
            return new ResponseEntity<>("refresh token null", HttpStatus.BAD_REQUEST);
        }


        try {
            jwtUtill.isExpired(refreshToken);
        } catch (ExpiredJwtException e) {
            return new ResponseEntity<>("refresh token expired", HttpStatus.BAD_REQUEST);
        }


        String category = jwtUtill.getCategory(refreshToken);
        if (!"refresh".equals(category)) {
            return new ResponseEntity<>("invalid refresh token", HttpStatus.BAD_REQUEST);
        }


        String username = jwtUtill.getUsername(refreshToken);
        String role = jwtUtill.getRole(refreshToken);


        String newAccessToken = jwtUtill.createJwt("access", username, role, 600000L);
        String newRefreshToken = jwtUtill.createJwt("refresh", username, role, 86400000L);


        response.setHeader("access", newAccessToken);
        response.addCookie(createCookie("refresh",newRefreshToken));


        return new ResponseEntity<>(HttpStatus.OK);
    }

    private Cookie createCookie(String key, String value) {

        Cookie cookie = new Cookie(key, value);
        cookie.setMaxAge(24 * 60 * 60);
        //cookie.setSecure(true);
        //cookie.setPath("/");
        cookie.setHttpOnly(true);

        return cookie;
    }
}
