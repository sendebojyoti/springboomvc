package com.in28minutes.springboot.web.security;

// import org.springframework.beans.factory.annotation.Autowired;
import org.apache.catalina.Context;
import org.apache.catalina.connector.Connector;
import org.apache.tomcat.util.descriptor.web.SecurityCollection;
import org.apache.tomcat.util.descriptor.web.SecurityConstraint;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.servlet.server.ServletWebServerFactory;
import org.springframework.context.annotation.Bean;
// import org.springframework.context.annotation.Configuration;
// import org.springframework.http.HttpMethod;
// import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
// import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

// @Configuration
// public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
@EnableWebSecurity
public class SecurityConfiguration {
	//Create User - in28Minutes/dummy
//	@Autowired
//    public void configureGlobalSecurity(AuthenticationManagerBuilder auth)
//            throws Exception {
//        auth.inMemoryAuthentication()
//            .passwordEncoder(NoOpPasswordEncoder.getInstance())
//        		.withUser("in28Minutes").password("dummy")
//                .roles("USER", "ADMIN");
//    }

    // We used the method User.withDefaultPasswordEncoder() for readability and course purpose.
    // It is not intended for PRODUCTION environment, and instead we recommend hashing your passwords externally
    @Bean
    public InMemoryUserDetailsManager userDetailsService() {
        UserDetails user = User.withDefaultPasswordEncoder()
                .username("in28Minutes")
                .password("dummy")
                .roles("ADMIN", "USER")
                .build();

        return new InMemoryUserDetailsManager(user);
    }

    // In Spring Security 5.4 introduced the ability to configure HttpSecurity by creating a SecurityFilterChain bean.
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeRequests((authorize) -> {
                    try {
                        authorize
                                .antMatchers("/login", "/h2-console/**").permitAll()
                                .antMatchers("/", "/*todo*/**").hasRole("USER")
                                .and().formLogin()
                                .and().csrf().disable()
                                .headers().frameOptions().disable();

                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                });


       // return http.build();


        return http
                .requiresChannel(channel ->
                        channel.anyRequest().requiresSecure())
                .authorizeRequests(authorize ->
                        authorize.anyRequest().permitAll())
                .build();
    }
	
//	Previous version that securing all endpoints with HTTP basic
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http.authorizeRequests().antMatchers("/login", "/h2-console/**").permitAll()
//                .antMatchers("/", "/*todo*/**").access("hasRole('USER')").and()
//                .formLogin();
//
//        http.csrf().disable();
//        http.headers().frameOptions().disable();
//    }

    @Bean
    public ServletWebServerFactory servletContainer() {
        TomcatServletWebServerFactory tomcat = new TomcatServletWebServerFactory() {
            @Override
            protected void postProcessContext(Context context) {
                var securityConstraint = new SecurityConstraint();
                securityConstraint.setUserConstraint("CONFIDENTIAL");
                var collection = new SecurityCollection();
                collection.addPattern("/*");
                securityConstraint.addCollection(collection);
                context.addConstraint(securityConstraint);
            }
        };
        tomcat.addAdditionalTomcatConnectors(getHttpConnector());
        return tomcat;
    }

    private Connector getHttpConnector() {
        var connector = new Connector(TomcatServletWebServerFactory.DEFAULT_PROTOCOL);
        connector.setScheme("http");
        connector.setPort(8080);
        connector.setSecure(false);
        connector.setRedirectPort(8443);
        return connector;
    }

}
