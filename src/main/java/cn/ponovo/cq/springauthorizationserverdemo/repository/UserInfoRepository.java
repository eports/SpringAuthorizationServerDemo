package cn.ponovo.cq.springauthorizationserverdemo.repository;

import cn.ponovo.cq.springauthorizationserverdemo.entities.UserInfo;
import org.springframework.stereotype.Repository;
import org.springframework.data.jpa.repository.JpaRepository;

@Repository
public interface UserInfoRepository extends JpaRepository<UserInfo, Long> {

    UserInfo findByUsername(String username);
}
