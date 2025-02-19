package com.authPractice.myapp.userController;

import com.authPractice.myapp.jwt.JwtUtils;
import com.authPractice.myapp.model.LoginRequest;
import com.authPractice.myapp.model.LoginResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.web.bind.annotation.*;

import javax.sql.DataSource;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class UserController {

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    DataSource dataSource;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtils jwtUtils;

    @PostMapping("/signup")
    public String createUser(@RequestParam String username ,
                             @RequestParam String password ,
                             @RequestParam String role){
        JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);

        if(jdbcUserDetailsManager.userExists(username)) return "user Already Exits";

        UserDetails userDetails = User.withUsername(username)
                .password(passwordEncoder.encode(password))
                .roles(role)
                .build();

        jdbcUserDetailsManager.createUser(userDetails);
        return "User created";
    }

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest){
        Authentication authentication;
        try{
            authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(),loginRequest.getPassword()));
            System.out.println(authentication.toString());
        }catch (AuthenticationException exception){
            //System.out.println(authentication.toString());
            Map<String , Object> map = new HashMap<>();
            map.put("message" , "Bad Credentials");
            map.put("status",false);
            return new ResponseEntity<Object>(map , HttpStatus.NOT_FOUND);
        }
        SecurityContextHolder.getContext().setAuthentication(authentication);
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        String jwtToken = jwtUtils.getUsernameFromToken(userDetails);

        List<String > roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        LoginResponse response = new LoginResponse(jwtToken,userDetails.getUsername() , roles);
        return ResponseEntity.ok(response);
    }

}
