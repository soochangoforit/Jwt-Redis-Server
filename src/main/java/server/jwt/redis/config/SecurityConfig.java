package server.jwt.redis.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import server.jwt.redis.exception.CustomAuthenticationEntryPoint;
import server.jwt.redis.jwt.*;
import server.jwt.redis.service.RequestService;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtProvider jwtProvider;
    private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;
    private final CustomAuthenticationManager customAuthenticationManager;
    private final RequestService requestService;
    private final CustomAuthorizationFilter customAuthorizationFilter;


    /**
     * SecurityFilterChain
     * Spring Security는 FilterChain 방식으로 인증 플로우가 진행된다.
     * cors와 csrf를 disable시킨다.
     *
     * authorizeRequests()를 통해 인증된 사용자만 접근할 수 있도록 설정한다.
     * antMatchers를 통해 특정 URI는 누구나 접근 가능하도록 설정 및 'ADMIN'의 룰을 가지는 유저만 접근 할 수 있도록 설정 가능하다.
     *
     * 기본적으로 UsernamePasswordAuthenticationFilter가 우선적으로 걸리는데 이 보다 앞에 추후에 직접 작성할 CustomJwtFilter를 설정하도록 할 예정이다
     *
     * exceptionHandling(), authenticationEntryPoint(customAuthenticationEntryPoint)
     *  - token을 validation했을 때, 만료 등의 invalid한 token에 대한 예외 처리가 필요하다
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        CustomAuthenticationFilter customAuthenticationFilter = new CustomAuthenticationFilter(customAuthenticationManager,jwtProvider,requestService);
        customAuthenticationFilter.setFilterProcessesUrl("/api/v1/user/login");

        http.cors().and().csrf().disable()
                .exceptionHandling()
                .authenticationEntryPoint(customAuthenticationEntryPoint)
                .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                .antMatchers("/api/v1/user/signup", "/api/v1/user/login", "/api/v1/user/refresh").permitAll()
                .antMatchers("/api/v1/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
                .and()
                .addFilter(customAuthenticationFilter)
                .addFilterBefore(customAuthorizationFilter, UsernamePasswordAuthenticationFilter.class);


        return http.build();

    }

}
