package org.wso2.is.swamedia;

import javax.servlet.http.HttpServletRequest;

import org.apache.oltu.oauth2.common.validators.AbstractValidator;

public class CustomPasswordGrantTypeValidator extends AbstractValidator<HttpServletRequest> {

	public CustomPasswordGrantTypeValidator() {
		requiredParams.add(CustomPasswordGrantType.USERNAME_GRANT_PARAM);
		requiredParams.add(CustomPasswordGrantType.PASSWORD_GRANT_PARAM);
	}
}
