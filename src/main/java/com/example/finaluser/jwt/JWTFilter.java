package com.example.finaluser.jwt;


import com.example.finaluser.dto.CustomOAuth2User;
import com.example.finaluser.dto.userDto;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;

public class JWTFilter extends OncePerRequestFilter {

    private final JWTUtill jwtUtill;

    public JWTFilter(JWTUtill jwtUtill) {
        this.jwtUtill = jwtUtill;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String requestUri = request.getRequestURI();
        if (requestUri.matches("^\\/login(?:\\/.*)?$") || requestUri.matches("^\\/oauth2(?:\\/.*)?$")) {
            filterChain.doFilter(request, response);
            return;
        }

        // 헤더에서 access키에 담긴 토큰을 꺼냄
        String accessToken = request.getHeader("access");

        // 토큰이 없다면 다음 필터로 넘김
        if (accessToken == null) {
            filterChain.doFilter(request, response);
            return;
        }

        // 토큰 만료 여부 확인, 만료시 다음 필터로 넘기지 않음
        try {
            jwtUtill.isExpired(accessToken);
        } catch (ExpiredJwtException e) {
            response.setContentType("text/plain");
            response.setCharacterEncoding("UTF-8");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().print("access token expired");
            return;
        }

        // 토큰이 access인지 확인 (발급시 페이로드에 명시)
        String category = jwtUtill.getCategory(accessToken);

        if (!"access".equals(category)) {
            response.setContentType("text/plain");
            response.setCharacterEncoding("UTF-8");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().print("invalid access token");
            return;
        }

        // username, role 값을 획득
        String username = jwtUtill.getUsername(accessToken);
        String role = jwtUtill.getRole(accessToken);

        // userDto 객체 생성
        userDto userDto = new userDto();
        userDto.setUsername(username);
        userDto.setRole(role);

        CustomOAuth2User customUserDetails = new CustomOAuth2User(userDto);

        // OAuth2AuthenticationToken 생성
        OAuth2User oAuth2User = new CustomOAuth2User(userDto);
        Authentication authToken = new OAuth2AuthenticationToken(oAuth2User, Collections.singleton(oAuth2User.getAuthorities().iterator().next()), "custom-client");

        SecurityContextHolder.getContext().setAuthentication(authToken);

        filterChain.doFilter(request, response);
    }
}
