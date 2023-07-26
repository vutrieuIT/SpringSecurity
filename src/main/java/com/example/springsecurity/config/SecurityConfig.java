package com.example.springsecurity.config;

import jakarta.servlet.Filter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor

// cấu hình bảo mật spring
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final AuthenticationProvider authenticationProvider;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(
                        (csrf) -> csrf.disable() // tắt csrf để phát triển, không khuyến nghị dùng trong thực tế
                )
                .authorizeHttpRequests(
                        (requests) -> requests
                                .requestMatchers("/api/v1/auth/**").permitAll() // cho phép mọi người truy cập
                                .anyRequest().authenticated() // mọi req khác phải xác thực
                )
                .sessionManagement(
                        // Cấu hình quản lý phiên (session) trong ứng dụng.
                        // chế độ tạo phiên được đặt thành STATELESS, tức là không sử dụng phiên
                        // và thông tin xác thực được gửi kèm theo mỗi yêu cầu.
                        (session) -> session
                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                // cung cấp 1 custom bean cho interface authProvider, được triển khai trong ApplicationConfig
                .authenticationProvider(authenticationProvider)
                // thêm bộ lọc jwt trước filter UsernamePasswordAuthenticationFilter của Spring
                // để xác thực jwt trước
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);


        return http.build();
    }
}
