package com.example.demo.conf;

import com.example.demo.conf.security.JWTAuthenticationFilter;
import com.example.demo.conf.security.JWTLoginFilter;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().passwordEncoder(passwordEncoder())
                .withUser("zhangsan").password("123456").roles("USER");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .formLogin().loginPage("/toLogin")//自定义登录页面
                .loginProcessingUrl("/login")//登录提交表单url
                .defaultSuccessUrl("/index")//登录成功后页面
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
                        httpServletResponse.addHeader("Content-Type", "text/html;charset=UTF-8");
                        if ("/api/login".equals(httpServletRequest.getRequestURI().toString())) {
                            httpServletResponse.getWriter().write("{\"error\":\"登录失败\"}");
                        } else {
                            httpServletResponse.getWriter().write("登录失败");
                        }
                    }
                })//登录失败处理
                .and().authorizeRequests()
                .antMatchers("/login").permitAll()//放行登录提交表单url
                .antMatchers("/toLogin").permitAll()//放行登录界面url
                .antMatchers("/api/login").permitAll()//放行api登录，获得jwt授权码
                .antMatchers("/**").authenticated() //所有路径都需要授权验证
                .and()
                .addFilterBefore(loginFilter(), UsernamePasswordAuthenticationFilter.class)//api登录处理逻辑过滤器
                .addFilterBefore(new JWTAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);//验证token是否合法过滤器
    }

    public JWTLoginFilter loginFilter() throws Exception {
        JWTLoginFilter loginFilter = new JWTLoginFilter(authenticationManager());
        loginFilter.setAuthenticationFailureHandler((request, response, exception) -> {
            response.setContentType("application/json");
            response.getWriter().write("{\"errormsg\":\"jwt认证失败\"}");
        });
        loginFilter.setContinueChainBeforeSuccessfulAuthentication(false);
        return loginFilter;
    }

    public PasswordEncoder passwordEncoder() {
        return new PasswordEncoder() {
            @Override
            public String encode(CharSequence charSequence) {
                return charSequence.toString();
            }

            @Override
            public boolean matches(CharSequence charSequence, String s) {
                return charSequence.toString().equals(s);
            }
        };
    }

}
