restful风格请求,基于token鉴权实例
=

如需源码请联系[程序帮](http://ll032.cn/HZ6vHa)：QQ1022287044

开发环境：
-----
1. jdk 8
2. intellij idea
3. maven 3.6

所用技术：
-----
1. springboot
2. restful

项目介绍
----
基于restful风格做的设计实例，即可jwt做token效验，实现增删查改,同时搭配自定义注解，方便过滤token验证

自定义注解
----
1.需要做验证的注解
``` diff
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface UserLoginToken {
    boolean required() default true;
}

//拦截类(AuthenticationInterceptor)代码
public boolean preHandle(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Object object) throws Exception {
    String token = httpServletRequest.getHeader("token");// 从 http 请求头中取出 token
    // 如果不是映射到方法直接通过
    if(!(object instanceof HandlerMethod)){
        return true;
    }
    HandlerMethod handlerMethod=(HandlerMethod)object;
    Method method=handlerMethod.getMethod();
    //检查是否有passtoken注释，有则跳过认证
    if (method.isAnnotationPresent(PassToken.class)) {
        PassToken passToken = method.getAnnotation(PassToken.class);
        if (passToken.required()) {
            return true;
        }
    }
    //检查有没有需要用户权限的注解
    if (method.isAnnotationPresent(UserLoginToken.class)) {
        UserLoginToken userLoginToken = method.getAnnotation(UserLoginToken.class);
        if (userLoginToken.required()) {
            // 执行认证
            if (token == null) {
                throw new RuntimeException("无token，请重新登录");
            }
            // 获取 token 中的 user id
            String userId;
            try {
                userId = JWT.decode(token).getAudience().get(0);
            } catch (JWTDecodeException j) {
                throw new RuntimeException("token error");
            }
            String user = jedis.get(userId);
            if (user == null) {
                throw new RuntimeException("用户不存在，请重新登录");
            }
            // 验证 token
            JSONObject jsonObject1=JSONObject.parseObject(user);
            JWTVerifier jwtVerifier = JWT.require(Algorithm.HMAC256(jsonObject1.getString("planType"))).build();
            try {
                jwtVerifier.verify(token);
            } catch (JWTVerificationException e) {
                throw new RuntimeException("token error");
            }
            return true;
        }
    }
    return true;
}

```

项目结构
----

- 项目结构图片

![项目结构](/image/项目结构图.jpg)

- 请求列表图片

![请求列表](/image/请求列表.jpg)


运行效果
----
- token 获取

![token 获取](/image/token获取.jpg)

```diff
@GetMapping("/token")
public JSONObject token(HttpServletResponse response ){
    Date timeOut=DateUtil.offsetMinute(new Date(),time);	//过期时间
    JSONObject jsonObject=new JSONObject();
    String usecase = new JWTController().getFile("usecase.json");
    JSONObject jsonObject1=JSONObject.parseObject(usecase);
    String token=JWT.create().withExpiresAt(timeOut).withAudience(jsonObject1.getString("objectId"))
            .sign(Algorithm.HMAC256(jsonObject1.getString("planType")));
    response.setStatus(200);
    jsonObject.put("token", token);
    jedis.set(jsonObject1.getString("objectId"), usecase);
    return jsonObject;
}
```

- 验证token

![验证token](/image/验证token.jpg)

```diff
//主要@UserLoginToken发挥验证作用，否则验证成功
@UserLoginToken
@GetMapping("/authToken")
public String getMessage(){
    return "身份验证成功 ";
}
```
- get 请求

![get 请求](/image/get 请求.jpg)

```diff
@UserLoginToken
@GetMapping(value="/plan/{id}")
public String getPlan(@PathVariable String id, HttpServletResponse response) {
    jedis.connect();
    if (jedis.get(id) == null) {
        response.setStatus(404);
        return "No such record";
    }
    response.setStatus(200);
    return jedis.get(id);
}
```

- post 请求

![post 请求](/image/post 请求.jpg)

```diff
@UserLoginToken
@ResponseBody
@PostMapping(path="/plan")
public String addPlan(@RequestBody JSONObject jsonObject, HttpServletResponse response) throws IOException, ProcessingException {
    String data = jsonObject.toString();
    Boolean jsonValidity = Validator.isJSONValid(data);
    if(jsonValidity) {
        String uuid = UUID.randomUUID().toString();
        jedis.set(uuid, data);
        return "Create Success" + "\n" + uuid;
    }
    else {
        response.setStatus(400);
        return "JSON Schema not valid!";
    }
}
```


- delete 请求

![delete 请求](/image/delete 请求.jpg)

```diff
@UserLoginToken
@DeleteMapping(value="/plan/{id}")
public String deletePlan(@PathVariable String id, HttpServletResponse response) {
    jedis.connect();
    if (jedis.get(id) == null) {
        response.setStatus(404);
        return "No such record";
    }
    jedis.del(id);
    response.setStatus(200);
    return "Deleted Success" + "\n" + id;
}
```

- patch 请求

![patch 请求](/image/patch 请求.jpg)

```diff
@UserLoginToken
@PatchMapping(value="/plan/{id}")
public String patchPlan(@RequestBody JSONObject jsonObject, @PathVariable String id, HttpServletResponse response) {
    jedis.connect();
    if (jedis.get(id) == null) {
        response.setStatus(404);
        return "No such record";
    }
    String data = jsonObject.toString();
    String redisDate=jedis.get(id);
    Map redisData=JSONUtil.toBean(redisDate,Map.class);
    Map map=JSONUtil.toBean(data,Map.class);
    for(Object o:map.keySet()){
        redisData.put(o,map.get(o));
    }
    jedis.set(id, JSONUtil.toJsonStr(redisData));
    response.setStatus(200);
    return "Patched Success" + "\n" + id;
}
```
- put 请求

![put 请求](/image/put 请求.jpg)

```diff
@UserLoginToken
@PutMapping(value="/plan/{id}")
public String updatePlan(@RequestBody JSONObject jsonObject, @PathVariable String id, HttpServletResponse response) throws IOException, ProcessingException {
    jedis.connect();
    if (jedis.get(id) == null) {
        response.setStatus(404);
        return "No such record";
    }
    String data = jsonObject.toString();
    if(Validator.isJSONValid(data)) {
        jedis.set(id, data);
        response.setStatus(200);
        return "Updated Success" + "\n" + id;
    }
    else {
        response.setStatus(400);
        return "Invalid JSON!";
    }
}
```
 

项目总结
----
1. restful 结合jwt做token效验，所有请求的token放入headers中
2. 项目还加入schema.json，Json Schema就是用来定义json数据约束的一个标准
3. 其他有更好的简洁操作习惯，希望留言交流

