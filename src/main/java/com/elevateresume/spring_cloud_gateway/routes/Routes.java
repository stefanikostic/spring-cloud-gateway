package com.elevateresume.spring_cloud_gateway.routes;

import org.springframework.cloud.gateway.server.mvc.handler.GatewayRouterFunctions;
import org.springframework.cloud.gateway.server.mvc.handler.HandlerFunctions;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.function.RequestPredicates;
import org.springframework.web.servlet.function.RouterFunction;
import org.springframework.web.servlet.function.ServerResponse;

@Configuration
public class Routes {

   /* @Bean
    public RouterFunction<ServerResponse> authService() {
        return GatewayRouterFunctions.route("user-service")
                .route(RequestPredicates.path("/auth/**"), HandlerFunctions.http("http://localhost:8081/"))
                .build();
    }*/
}
