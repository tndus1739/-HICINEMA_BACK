package com.himedia.hicinema;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity // 스프링 시큐리티 필터가 스프링 필터체인에 등록이 됨
public class SecurityConfig {
	@Bean
	SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		
	   // 타임리프로 제작한 login/register form에 csrf 토큰을 삽입하는(자동으로 삽입됨) 과정에서 템플릿 파싱 오류발생
       // 오류 : 'cannot create a session after the response has been committed'
		
	   // 해결
		http 
			.sessionManagement((sessionManagement) -> sessionManagement
					.sessionCreationPolicy(SessionCreationPolicy.ALWAYS)
					)
			; 
		
		http
		
				.authorizeHttpRequests((authorizeHttpRequests) -> authorizeHttpRequests
						.requestMatchers(new AntPathRequestMatcher("/**")).permitAll()
						)
				// 로그인
				.formLogin((formLogin) -> formLogin
		                .loginPage("/member/login")
		                .usernameParameter("memberId")  // username과 다르면 명시해야함 
		                .passwordParameter("password")
		                .defaultSuccessUrl("/"))
				// 로그아웃
				.logout((logout) -> logout
						
		                .logoutRequestMatcher(new AntPathRequestMatcher("/member/logout"))
		                .logoutSuccessUrl("/")
		                .invalidateHttpSession(true))   //생성된 사용자 세션도 삭제
				
				;
		
		return http.build();
	}
	
	
	@Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
	
	@Bean
	    AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
	        return authenticationConfiguration.getAuthenticationManager();
	    }
	
}