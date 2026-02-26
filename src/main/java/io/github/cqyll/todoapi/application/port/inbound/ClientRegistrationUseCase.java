package io.github.cqyll.todoapi.application.port.inbound;

import io.github.cqyll.todoapi.dto.ClientRegistrationRequest;
import io.github.cqyll.todoapi.dto.ClientRegistrationResponse;

public interface ClientRegistrationUseCase {
    ClientRegistrationResponse register(ClientRegistrationRequest req);
}