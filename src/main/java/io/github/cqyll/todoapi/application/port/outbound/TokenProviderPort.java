package io.github.cqyll.todoapi.application.port.outbound;


public interface TokenProviderPort {
	String createToken(String subject); // subject = userId | clientId
}
