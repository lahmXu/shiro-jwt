package com.lahmxu.example.shiro;

import com.lahmxu.example.biz.entity.UserEntity;
import com.lahmxu.example.common.jwt.JwtToken;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

import java.util.Set;

public class JwtRealm extends AuthorizingRealm {

    @Override
    public boolean supports(AuthenticationToken token) {
        return token instanceof JwtToken;
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        UserEntity currentUser = (UserEntity) SecurityUtils.getSubject().getPrincipal();

        Set<String> roles = ShiroRealm.roleMap.get(currentUser.getName());
        Set<String> perms = ShiroRealm.permMap.get(currentUser.getName());

        SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
        authorizationInfo.setRoles(roles);
        authorizationInfo.setStringPermissions(perms);
        return authorizationInfo;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        JwtToken jwtToken = (JwtToken) authenticationToken;
        if (jwtToken.getPrincipal() == null) {
            throw new AccountException("JWT Token参数异常！");
        }
        String username = jwtToken.getPrincipal().toString();

        UserEntity user = ShiroRealm.userMap.get(username);

        if (user == null) {
            throw new UnknownAccountException("用户不存在");
        }

        if (user.getLocked()) {
            throw new LockedAccountException("该用户已被锁定，暂时无法登陆！");
        }

        SimpleAuthenticationInfo authenticationInfo = new SimpleAuthenticationInfo(user, username, getName());
        return authenticationInfo;
    }
}
