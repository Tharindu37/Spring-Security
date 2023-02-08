package com.developerstack.security.api;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("api/v1/orders")
public class OrderController {
    @PostMapping
    public String createOrder(){return "createOrder";}
    @GetMapping
    public String findOrder(){return "findOrder";}
    @DeleteMapping
    public String deleteOrder(){return "deleteOrder";}
    @PutMapping
    public String updateOrder(){return "updateOrder";}
    @GetMapping("/list")
    public String getAllOrder(){return "getAllOrder";}
}
