package cn.ponovo.cq.springauthorizationserverdemo.entities;

import jakarta.persistence.*;
import lombok.Data;

@Data
@Table()
@Entity( name = "t_user")
public class UserInfo {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY )
    private long id;

    @Column(name = "user_name")
    private String username;

    private String password;

}
