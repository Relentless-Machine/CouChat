package com.couchat.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable()) // 禁用CSRF保护，特别是对于API
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/api/messages/**").permitAll() // 允许对/api/messages/下的所有请求
                .requestMatchers("/api/auth/**").permitAll() // 假设将来会有/api/auth用于登录等，也允许
                // .anyRequest().authenticated() // 对于原型，暂时允许所有其他请求，或根据需要调整
                .anyRequest().permitAll()
            )
            // 对于无状态API，通常将session管理设置为STATELESS
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            // 如果需要Spring Boot默认的登录页面（如果anyRequest().authenticated()启用了），可以取消注释以下内容
            // .formLogin(withDefaults())
            // .httpBasic(withDefaults())
            ;
        return http.build();
    }
}

