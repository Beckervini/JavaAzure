package com.project.cleanenerg.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf().disable() // Desativa CSRF para facilitar os testes
            .authorizeHttpRequests()
                .anyRequest().permitAll() // Permite todas as requisições
            .and()
            .headers().frameOptions().disable(); // Libera o uso do H2 Console

        return http.build();
    }
}
