package com.developerstack.security.api;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/customer")
public class CustomerController {
    @PostMapping
    public String createCustomer(){return "createCustomer";}
    @GetMapping
    public String findCustomer(){return "findCustomer";}
    @DeleteMapping
    public String deleteCustomer(){return "deleteCustomer";}
    @PutMapping
    public String updateCustomer(){return "updateCustomer";}
    @GetMapping("/list")
    public String getAllCustomer(){return "getAllCustomer";}

}
