package com.developerstack.security.config.permission;

public enum ApplicationUserPermission {
    ORDER_READ("order:read"),
    ORDER_WRITE("order:write"),
    PRODUCT_READ("product:read"),
    PRODUCT_WRITE("product:write"),
    CUSTOMER_READ("customer:read"),
    CUSTOMER_WRITE("customer:write");

    private final String permission;


    ApplicationUserPermission(String permission) {
        this.permission = permission;
    }

    public String getPermission(){
        return permission;
    }
}
