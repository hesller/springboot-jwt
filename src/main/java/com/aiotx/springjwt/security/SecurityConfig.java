package com.aiotx.springjwt.security;

import com.aiotx.springjwt.filter.CustomAuthenticationFilter;
import com.aiotx.springjwt.filter.CustomAuthorizationFilter;
import com.aiotx.springjwt.repository.UserRepository;
import com.aiotx.springjwt.services.Service;
import com.aiotx.springjwt.services.ServiceImplementation;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static com.aiotx.springjwt.security.ApplicationUserPermission.*;
import static com.aiotx.springjwt.security.ApplicationUserRole.*;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@Configuration @EnableWebSecurity @RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;

    @Override
    @Bean
    protected UserDetailsService userDetailsService() {

        UserDetails hadesh = User.builder()
                .username("hadesh")
                .password(passwordEncoder.encode("123456"))
//                .roles(SUPER_ADMIN.getRole())
                .authorities(SUPER_ADMIN.getGrantedAuthorities())
                .build();

        UserDetails marcosFelipe = User.builder()
                .username("marcos")
                .password(passwordEncoder.encode("123456"))
//                .roles(ADMIN.getRole())
                .authorities(ADMIN.getGrantedAuthorities())
                .build();

        UserDetails andre = User.builder()
                .username("andre")
                .password(passwordEncoder.encode("123456"))
//                .roles(ADMIN.getRole())
                .authorities(MANAGER.getGrantedAuthorities())
                .build();

        UserDetails pedrinho = User.builder()
                .username("pedrinho")
                .password(passwordEncoder.encode("123456"))
//                .roles(USER.getRole())
                .authorities(USER.getGrantedAuthorities())
                .build();


        return new InMemoryUserDetailsManager(
                marcosFelipe,
                pedrinho,
                hadesh,
                andre
        );
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService()).passwordEncoder(passwordEncoder);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        CustomAuthenticationFilter customAuthenticationFilter = new CustomAuthenticationFilter(authenticationManagerBean());
        customAuthenticationFilter.setFilterProcessesUrl("/api/login");
        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(STATELESS);
        http.authorizeRequests().antMatchers("/api/login/**").permitAll();
        http.authorizeRequests().antMatchers(GET, "/api/users").hasAnyRole(MANAGER.getRole(), ADMIN.getRole(), SUPER_ADMIN.getRole());
        http.authorizeRequests().antMatchers(GET, "/api/user/**").hasAuthority("ROLE_USER");
        http.authorizeRequests().antMatchers(GET, "/api/user/**").hasAuthority("ROLE_MANAGER");
        http.authorizeRequests().antMatchers(POST, "/api/user/save/**").hasAuthority(MANAGER_WRITE.getPermission());
        http.authorizeRequests().antMatchers(POST, "/api/role/save/**").hasAuthority(SUPER_ADMIN_WRITE.getPermission());
        http.authorizeRequests().antMatchers(GET, "/api/roles").hasAnyAuthority(ADMIN_READ.getPermission());
        http.authorizeRequests().anyRequest().authenticated(); /* this is here only for sake of example */

        http.addFilter(customAuthenticationFilter);
        http.addFilterBefore(new CustomAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
