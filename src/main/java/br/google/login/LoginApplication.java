package br.google.login;

import java.util.Collections;
import java.util.Map;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@RestController
public class LoginApplication{

	@GetMapping("/user")
    public Map<String, Object> user(@AuthenticationPrincipal OAuth2User principal) {
        return Collections.singletonMap("name", principal.getAttribute("name"));
    }

	public static void main(String[] args) {
		SpringApplication.run(LoginApplication.class, args);
	}

	@Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    	// @formatter:off
        http
            .authorizeRequests(a -> a
                .antMatchers("/", "/error", "/webjars/**").permitAll()
                .anyRequest().authenticated()
            )
			.logout(l -> l
            .logoutSuccessUrl("/").permitAll()
        	)
			.csrf(c -> c
            .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
        	)
            .exceptionHandling(e -> e
                .authenticationEntryPoint((AuthenticationEntryPoint) new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
            )
            .oauth2Login();
        // @formatter:on
		return http.build();
    }



}
