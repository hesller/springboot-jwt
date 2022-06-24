package com.aiotx.springjwt.security;

import com.aiotx.springjwt.auth.ApplicationUserService;
import com.aiotx.springjwt.filter.JwtAuthorizationFilter;
import com.aiotx.springjwt.filter.JwtConfig;
import com.aiotx.springjwt.filter.JwtCustomAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static com.aiotx.springjwt.security.ApplicationUserPermission.*;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@Configuration @EnableWebSecurity @RequiredArgsConstructor @EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final ApplicationUserService userService;
    private final PasswordEncoder passwordEncoder;
    private final JwtConfig jwtConfig;

//    @Override
//    @Bean
//    protected UserDetailsService userDetailsService() {
//
//        UserDetails hadesh = User.builder()
//                .username("hadesh")
//                .password(passwordEncoder.encode("123456"))
////                .roles(SUPER_ADMIN.getRole())
//                .authorities(SUPER_ADMIN.getGrantedAuthorities())
//                .build();
//
//        UserDetails marcosFelipe = User.builder()
//                .username("marcos")
//                .password(passwordEncoder.encode("123456"))
////                .roles(ADMIN.getRole())
//                .authorities(ADMIN.getGrantedAuthorities())
//                .build();
//
//        UserDetails andre = User.builder()
//                .username("andre")
//                .password(passwordEncoder.encode("123456"))
////                .roles(ADMIN.getRole())
//                .authorities(MANAGER.getGrantedAuthorities())
//                .build();
//
//        UserDetails pedrinho = User.builder()
//                .username("pedrinho")
//                .password(passwordEncoder.encode("123456"))
////                .roles(USER.getRole())
//                .authorities(USER.getGrantedAuthorities())
//                .build();
//
//
//        return new InMemoryUserDetailsManager(
//                marcosFelipe,
//                pedrinho,
//                hadesh,
//                andre
//        );
//    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.userDetailsService(userService).passwordEncoder(passwordEncoder);
        auth.authenticationProvider(daoAuthenticationProvider());
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(userService);
        return provider;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        JwtCustomAuthenticationFilter customAuthenticationFilter = new JwtCustomAuthenticationFilter(authenticationManager(), jwtConfig);
        customAuthenticationFilter.setFilterProcessesUrl("/api/login");
        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(STATELESS);
        http.addFilter(customAuthenticationFilter);
        http.addFilterAfter(new JwtAuthorizationFilter(jwtConfig), UsernamePasswordAuthenticationFilter.class);
        http.authorizeRequests().antMatchers("/api/login/**").permitAll();
        http.authorizeRequests().antMatchers(GET, "/api/user/**").hasAuthority("ROLE_MANAGER");
        http.authorizeRequests().antMatchers(POST, "/api/user/save/**").hasAuthority(MANAGER_WRITE.getPermission());
        http.authorizeRequests().antMatchers(POST, "/api/role/save/**").hasAuthority(SUPER_ADMIN_WRITE.getPermission());
        http.authorizeRequests().anyRequest().authenticated(); /* this is here only for sake of example */


//        http
//                .csrf().disable()
//                .authorizeRequests()
//                .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
//                .antMatchers(POST, "/api/user/save/**").hasAuthority(MANAGER_WRITE.getPermission())
//                .antMatchers("/api/**").hasAnyRole(ADMIN.getRole(), SUPER_ADMIN.getRole())
//                .anyRequest()
//                .authenticated()
//                .and()
//                .formLogin()
////                .loginPage("/login").permitAll()
//                    .defaultSuccessUrl("/dashboard", true)
//                    .passwordParameter("password")
//                    .usernameParameter("username")
//                .and()
//                .rememberMe()
//                    .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))
//                    .key("somethingverysecured")
//                .and()
//                .logout()
//                    .logoutUrl("/logout")
//                    .clearAuthentication(true)
//                    .invalidateHttpSession(true)
//                    .deleteCookies("JSESSIONID", "remember-me")
//                    .logoutSuccessUrl("/login");

    }
}
