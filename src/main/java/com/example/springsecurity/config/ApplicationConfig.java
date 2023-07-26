package com.example.springsecurity.config;

import com.example.springsecurity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@RequiredArgsConstructor
// lớp triên khai các custom interface của Spring Security
public class ApplicationConfig {

    private final UserRepository userRepository;

    @Bean
    // interface lấy thông tin người dùng từ nguồn dữ liệu
    // Bean lấy thông tin người dùng từ database
    public UserDetailsService userDetailsService() {
        return username -> userRepository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("user not found"));
    }

    @Bean
    // Interface cung cấp cơ chế xác thực (authentication) cho người dùng
    // Bean được Security dùng để xác thực người dùng thông qua
    // bean userDetailsService(), passwordEncoder()
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService());
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        return authenticationProvider;
    }

    @Bean
    // interface với method authenticate() làm nhiệm vụ xác định những Authentication providers
    // phù hợp nhất để xử lý Authentication object nhận được từ filters
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    // interface có nhiệm vụ encode, encrypt và decrypt password của user
    // bean cung cấp thuật BCryptPasswordEncoder()
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
