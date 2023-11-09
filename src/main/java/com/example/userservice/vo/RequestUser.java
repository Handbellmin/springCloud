package com.example.userservice.vo;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class RequestUser {
    @NotNull(message = "Email cannot be null")
    @Size(min=2,message = "Email not be less than two charactrers")
    @Email
    private String email;
    @NotNull(message = "Name cannot be null")
    @Size(min=2,message = "Name not be less than two charactrers")
    private String name;
    @NotNull(message = "Password cannot be null")
    @Size(min=8,message = "Password not be less than two charactrers")
    private String pwd;
}
