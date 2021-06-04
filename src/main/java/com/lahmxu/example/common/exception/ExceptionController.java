package com.lahmxu.example.common.exception;

import com.lahmxu.example.common.base.BaseResponse;
import org.apache.shiro.ShiroException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import javax.servlet.http.HttpServletRequest;

/**
 * 处理全局异常
 * @author lahmxu
 */
@RestControllerAdvice
public class ExceptionController {

    @ExceptionHandler(ShiroException.class)
    public Object handleShiroException(ShiroException e){
        BaseResponse<Object> result = new BaseResponse<>();
        result.setErrCode(401);
        result.setMsg(e.getMessage());
        return result;
    }

    @ExceptionHandler(Exception.class)
    public Object globalException(HttpServletRequest request, Throwable ex) {
        BaseResponse<Object> result = new BaseResponse<>();
        result.setErrCode(401);
        result.setMsg(ex.getMessage());
        return result;
    }
}
