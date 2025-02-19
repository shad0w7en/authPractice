package com.authPractice.myapp.testController;

import com.authPractice.myapp.jwt.JwtUtils;
import com.authPractice.myapp.model.LoginRequest;
import com.authPractice.myapp.model.LoginResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class GreetingController {



    @GetMapping("/test")
    public String testMethod(){
        return "Working";
    }

    @GetMapping("/hello")
    public String greeting(){
        return "Hellow";
    }

    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @GetMapping("/admin")
    public String adminEndpoint(){
        return "Hello ADMIN";
    }


    @PreAuthorize("hasRole('ROLE_USER')")
    @GetMapping("/user")
    public String userEndPoint(){
        return "Hello User";
    }



}
