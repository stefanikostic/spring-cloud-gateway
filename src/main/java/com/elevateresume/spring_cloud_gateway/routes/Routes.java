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

    private static final String USER_SERVICE = "user-service";
    private static final String AUTH_PATTERN = "/auth/**";
    private static final String EXTERNAL_RESUME_PATH = "external/resume/**";
    private static final String INTERNAL_RESUME_PATH = "internal/resume/**";
    private static final String RESUME_PATH = "resume/**";
    private static final String PREVIEW_RESUME_PATH = "/preview-resume/**";

    @Bean
    public RouterFunction<ServerResponse> authService() {
        return GatewayRouterFunctions.route(USER_SERVICE)
                .route(RequestPredicates.path(AUTH_PATTERN),
                        HandlerFunctions.http("http://localhost:8081/")).build();
    }

    @Bean
    public RouterFunction<ServerResponse> resumeService() {
        return RouterFunctions
                .route()
                .route(RequestPredicates.path(EXTERNAL_RESUME_PATH),
                        request -> HandlerFunctions.http("http://localhost:8082/").handle(request))
                .route(RequestPredicates.path(INTERNAL_RESUME_PATH),
                        request -> HandlerFunctions.http("http://localhost:8082/").handle(request))
                .route(RequestPredicates.path(RESUME_PATH),
                        request -> HandlerFunctions.http("http://localhost:8082/").handle(request))
                .build();
    }

    @Bean
    public RouterFunction<ServerResponse> previewResumeService() {
        return RouterFunctions.route(RequestPredicates.path(PREVIEW_RESUME_PATH), request -> HandlerFunctions.http("http://localhost:8083/").handle(request));
    }
}
