package io.agentguard.orders;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration(proxyBeanMethods = false)
public class SecurityConfiguration {
    @Bean
    UserDetailsService demoUsers() {
        var encoder = new BCryptPasswordEncoder();
        return new InMemoryUserDetailsManager(
            User.withUsername("developer").password(encoder.encode("demo-pass")).roles("DEVELOPER").build(),
            User.withUsername("operator").password(encoder.encode("demo-pass")).roles("OPERATOR").build(),
            User.withUsername("approver").password(encoder.encode("demo-pass")).roles("APPROVER").build(),
            User.withUsername("auditor").password(encoder.encode("demo-pass")).roles("AUDITOR").build());
    }

    @Bean
    BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    SecurityFilterChain security(HttpSecurity http) throws Exception {
        return http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
            .formLogin(form -> form.defaultSuccessUrl("/", true))
            .httpBasic(Customizer.withDefaults())
            .exceptionHandling(errors -> errors.defaultAuthenticationEntryPointFor(
                new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED), new AntPathRequestMatcher("/api/**")))
            // Keep CSRF protection for browser sessions and Basic-auth API callers.
            .build();
    }
}
