package com.developerstack.security.api;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/member/api/v1/products")
public class ProductController {
    @PostMapping
    @PreAuthorize("hasAuthority('product:write')")
    public String createProduct(){return "createProduct";}
    @GetMapping
    @PreAuthorize("hasAnyRole('ROLE_ADMIN','ROLE_MANAGER')")
    public String findProduct(){return "findProduct";}
    @DeleteMapping
    @PreAuthorize("hasAuthority('product:write')")
    public String deleteProduct(){return "deleteProduct";}
    @PutMapping
    @PreAuthorize("hasAuthority('product:write')")
    public String updateProduct(){return "updateProduct";}
    @GetMapping("/list")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN','ROLE_MANAGER')")
    public String getAllProduct(){return "getAllProduct";}
}
