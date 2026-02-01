package org.kunievakateryna.filter;

import org.kunievakateryna.auth.GoogleAuthenticationService;
import org.kunievakateryna.service.SessionService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
public class AuthenticationFilter implements GlobalFilter, Ordered {

    private static final String PREFIX_OAUTH = "/oauth";
    private static final String ENDPOINT_AUTHENTICATE = PREFIX_OAUTH + "/authenticate";
    private static final String ENDPOINT_CALLBACK = PREFIX_OAUTH + "/callback";
    public static final String COOKIE_REDIRECT_TO = "redirect-to";
    public static final String COOKIE_AUTH_STATE = "auth-state";
    public static final String COOKIE_SESSION_ID = "SESSION-ID";

    private final GoogleAuthenticationService googleAuthenticationService;

    private final SessionService sessionService;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        return switch (request.getPath().value()) {
            case ENDPOINT_AUTHENTICATE -> authenticate(exchange);
            case ENDPOINT_CALLBACK -> authCallback(exchange);
            default -> chain.filter(exchange);
        };
    }

    private Mono<Void> authenticate(ServerWebExchange exchange) {
        String state = UUID.randomUUID().toString();
        
        String redirectTo = exchange.getRequest().getQueryParams()
                .getOrDefault("redirectTo", List.of("/")).getFirst();

        addStateCookie(exchange, state);
        
        exchange.getResponse().addCookie(ResponseCookie.from(COOKIE_REDIRECT_TO)
                .value(redirectTo)
                .path(PREFIX_OAUTH)
                .maxAge(Duration.of(30, ChronoUnit.MINUTES))
                .secure(false) 
                .httpOnly(true)
                .build());

        String redirectUri = buildRedirectUri(exchange.getRequest());
        String authenticationUrl = googleAuthenticationService.generateAuthenticationUrl(redirectUri, state);
        return sendRedirect(exchange, authenticationUrl);
    }

    private Mono<Void> authCallback(ServerWebExchange exchange) {
        String code = exchange.getRequest().getQueryParams().getFirst("code");
        String state = exchange.getRequest().getQueryParams().getFirst("state");
        String redirectUri = buildRedirectUri(exchange.getRequest());

        HttpCookie redirectCookie = exchange.getRequest().getCookies().getFirst(COOKIE_REDIRECT_TO);
        String targetUrl = (redirectCookie != null) ? redirectCookie.getValue() : "/";

        return verifyState(state, exchange.getRequest())
                .then(googleAuthenticationService.processAuthenticationCallback(code, redirectUri)
                              .flatMap(sessionService::saveSession)
                              .flatMap(session -> sessionService.addSessionCookie(exchange, session))
                              .then(sendRedirect(exchange, targetUrl)));
    }

    private Mono<Void> verifyState(String state, ServerHttpRequest request) {
        HttpCookie cookie = request.getCookies().getFirst(COOKIE_AUTH_STATE);
        if (cookie == null || !state.equals(cookie.getValue())) {
            return Mono.error(new IllegalStateException("Invalid state or cookie missing"));
        }
        return Mono.empty();
    }

    private static void addStateCookie(ServerWebExchange exchange, String state) {
        exchange.getResponse().addCookie(ResponseCookie.from(COOKIE_AUTH_STATE)
                                                 .value(state)
                                                 .path(PREFIX_OAUTH)
                                                 .maxAge(Duration.of(30, ChronoUnit.MINUTES))
                                                 .secure(false)
                                                 .build());
    }

    private static Mono<Void> sendRedirect(ServerWebExchange exchange, String location) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.FOUND);
        response.getHeaders().add("Location", location);
        return response.setComplete();
    }

    private String buildRedirectUri(ServerHttpRequest request) {
        String baseUrl = getBaseUrl(request);
        return baseUrl + ENDPOINT_CALLBACK;
    }

    private static String getBaseUrl(ServerHttpRequest request) {
        return request.getURI().toString().substring(0, request.getURI().toString().indexOf(PREFIX_OAUTH));
    }

    @Override
    public int getOrder() {
        return -10;
    }

}
