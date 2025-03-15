package com.elevateresume.spring_cloud_gateway.routes;

import org.springframework.cloud.gateway.server.mvc.handler.GatewayRouterFunctions;
import org.springframework.cloud.gateway.server.mvc.handler.HandlerFunctions;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.function.RequestPredicates;
import org.springframework.web.servlet.function.RouterFunction;
import org.springframework.web.servlet.function.RouterFunctions;
import org.springframework.web.servlet.function.ServerResponse;

@Configuration
public class Routes {

    @Bean
    public RouterFunction<ServerResponse> authService() {
        return GatewayRouterFunctions.route("user-service").route(RequestPredicates.path("/auth/**"), HandlerFunctions.http("http://localhost:8081/")).build();
    }

    @Bean
    public RouterFunction<ServerResponse> resumeService() {
        return RouterFunctions.route(RequestPredicates.path("/resume/**"), request -> HandlerFunctions.http("http://localhost:8082/").handle(request));
    }

    @Bean
    public RouterFunction<ServerResponse> previewResumeService() {
        return RouterFunctions.route(RequestPredicates.path("/preview-resume/**"), request -> HandlerFunctions.http("http://localhost:8083/").handle(request));
    }
}
