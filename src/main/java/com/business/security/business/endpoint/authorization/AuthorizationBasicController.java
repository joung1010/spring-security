package com.business.security.business.endpoint.authorization;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * <b> AuthorizationBasicController </b>
 *
 * @author jh.park
 * @version 0.1.0
 * @since 2025-04-07
 */

@Slf4j
@RestController
public class AuthorizationBasicController {
    @GetMapping("/user")
    public String user(){
        return "user";
    }

    @GetMapping("/user/{name}")
    public String userName(@PathVariable String name){
        return name;
    }

    @GetMapping("/admin/db")
    public String adminDb(){
        return "admin";
    }

    @GetMapping("/myPage/points")
    public String myPage(){
        return "myPage";
    }

    @GetMapping("/manager")
    public String manager(){
        return "manager";
    }

    @GetMapping("/admin")
    public String admin(){
        return "admin";
    }

    @GetMapping("/admin/payment")
    public String adminPayment(){
        return "adminPayment";
    }

    @GetMapping("/resource/address_01")
    public String address_01(){
        return "address_01";
    }

    @GetMapping("/resource/address01")
    public String address01(){
        return "address01";
    }

    @PostMapping("/post")
    public String post(){
        return "post";
    }


    @GetMapping("/custom")
    public String custom(){
        return "custom";
    }

    @GetMapping("/api/photos")
    public String photos(){
        return "photos";
    }


    @GetMapping("/oauth/login")
    public String oauthLogin(){
        return "oauthLogin";
    }
}
