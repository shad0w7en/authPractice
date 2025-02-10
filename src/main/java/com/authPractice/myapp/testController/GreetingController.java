package com.authPractice.myapp.testController;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class GreetingController {

    @GetMapping("/hello")
    public String greeting(){
        return "Hellow";
    }

    @PreAuthorize("hasRole('admin')")
    @GetMapping("/admin")
    public String adminEndpoint(){
        return "Hello ADMIN";
    }
    @PreAuthorize("hasRole('user')")
    @GetMapping("/user")
    public String userEndPoint(){
        return "Hello User";
    }
}
