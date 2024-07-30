package com.example.finaluser.config;


import jakarta.servlet.http.HttpServletRequest;
import com.example.finaluser.jwt.JWTFilter;
import com.example.finaluser.jwt.JWTUtill;
import com.example.finaluser.oauth2.CustomSuccessHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import com.example.finaluser.service.CustomOAuth2UserService;

import java.util.Collections;


@Configuration
@EnableWebSecurity

public class SecurityConfig {

    private final CustomOAuth2UserService customOAuth2UserService;

   private final CustomSuccessHandler customSuccessHandler;
   private final JWTUtill jwtUtill;


    public SecurityConfig(CustomOAuth2UserService customOAuth2UserService, CustomSuccessHandler customSuccessHandler,JWTUtill jwtUtill) {

        this.customOAuth2UserService = customOAuth2UserService;
        this.customSuccessHandler = customSuccessHandler;
        this.jwtUtill = jwtUtill;

    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                .cors(corsCustomizer -> corsCustomizer.configurationSource(new CorsConfigurationSource() {
                    @Override
                    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {

                        CorsConfiguration configuration = new CorsConfiguration();

                        configuration.setAllowedOrigins(Collections.singletonList("http://localhost:3000"));//앞단 프론트 주소
                        configuration.setAllowedMethods(Collections.singletonList("*"));
                        configuration.setAllowCredentials(true);
                        configuration.setAllowedHeaders(Collections.singletonList("*"));
                        configuration.setMaxAge(3600L);

                        configuration.setExposedHeaders(Collections.singletonList("Set-Cookie"));//쿠키반환
                        configuration.setExposedHeaders(Collections.singletonList("Authorization"));

                        return configuration;
                    }
                }));

        // CSRF 비활성화
        http
                .csrf(csrf -> csrf.disable());

        // Form 로그인 비활성화
        http
                .formLogin(formLogin -> formLogin.disable());

        // HTTP Basic 인증 방식 비활성화
        http
                .httpBasic(httpBasic -> httpBasic.disable());

        //JWTFilter
        http
                .addFilterAfter(new JWTFilter(jwtUtill), OAuth2LoginAuthenticationFilter.class);

        // OAuth2 로그인 설정
        http.oauth2Login(oauth2 -> oauth2
                .userInfoEndpoint(userInfoEndpoint -> userInfoEndpoint
                        .userService(customOAuth2UserService))
                .successHandler(customSuccessHandler)
        );

        // 경로별 인가 작업
        http.authorizeHttpRequests(auth -> auth
                .requestMatchers("/").permitAll()
                .requestMatchers("/reissue").permitAll()
                .anyRequest().authenticated()
        );

        // 세션 설정 : STATELESS
        // JWT로 인증/인가를 진행할 것이기 때문에 STATELESS로 설정
        http.sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        );

        return http.build();
    }
}
