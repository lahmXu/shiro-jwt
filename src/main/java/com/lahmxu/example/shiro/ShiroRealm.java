package com.lahmxu.example.shiro;

import com.lahmxu.example.biz.entity.UserEntity;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class ShiroRealm extends AuthorizingRealm {

    @Override
    public boolean supports(AuthenticationToken token) {
        return token instanceof UsernamePasswordToken;
    }

    /**
     * 返回权限信息
     * @param principalCollection
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        UserEntity currentUser = (UserEntity) SecurityUtils.getSubject().getPrincipal();
        Set<String> roles = roleMap.get(currentUser.getName());
        Set<String> perms = permMap.get(currentUser.getName());

        SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
        authorizationInfo.setRoles(roles);
        authorizationInfo.setStringPermissions(perms);
        return authorizationInfo;
    }

    /**
     * 返回用户信息
     * @param authenticationToken
     * @return
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {

        String username = authenticationToken.getPrincipal().toString();

        UserEntity user = userMap.get(username);

        if (user == null) {
            throw new UnknownAccountException("用户不存在");
        }

        if (user.getLocked()) {
            throw new LockedAccountException("该用户已被锁定，暂时无法登陆！");
        }

        ByteSource credentialsSalt = ByteSource.Util.bytes(username);

        SimpleAuthenticationInfo AuthenticationInfo = new SimpleAuthenticationInfo(user, user.getPassword(), credentialsSalt, getName());
        return AuthenticationInfo;
    }


    public static Map<String, UserEntity> userMap = new HashMap<String, UserEntity>(16);
    public static Map<String, Set<String>> roleMap = new HashMap<String, Set<String>>(16);
    public static Map<String, Set<String>> permMap = new HashMap<String, Set<String>>(16);

    static {
        UserEntity user1 = new UserEntity(1L, "graython", "dd524c4c66076d1fa07e1fa1c94a91233772d132", "灰先生", false);
        UserEntity user2 = new UserEntity(2L, "plum", "cce369436bbb9f0325689a3a6d5d6b9b8a3f39a0", "李先生", false);

        userMap.put("graython", user1);
        userMap.put("plum", user2);

        roleMap.put("graython", new HashSet<String>() {
            {
                add("admin");

            }
        });

        roleMap.put("plum", new HashSet<String>() {
            {
                add("guest");
            }
        });
        permMap.put("plum", new HashSet<String>() {
            {
                add("article:read");
            }
        });
    }
}
