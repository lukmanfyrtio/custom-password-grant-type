## How to apply custom password grant type to Identity Server version 5.7.0

System Requirements
=========================================

1. Install Java SE Development Kit 8
2. Install Apache Maven 3.x.x(https://maven.apache.org/download.cgi#)

=========================================

Follow the below steps to apply custom password grant type:

1. To generate the `.jar` file, navigate to the source code location using the command line and run the following Apache Maven command:

```shell
mvn clean install -Dmaven.test.skip=true
```

2. Copy the .jar file into the <IS_HOME>/repository/component/lib directory. You can also modify the project and build it using Apache Maven 3.

3. Configure the following in the <IS_HOME>/repository/conf/identity/identity.xml file under the <OAuth><SupportedGrantTypes> element.
```bash
  <SupportedGrantType>
      <GrantTypeName>custom_password</GrantTypeName>
      <GrantTypeHandlerImplClass>org.wso2.is.swamedia.CustomPasswordGrantType</GrantTypeHandlerImplClass>
      <GrantTypeValidatorImplClass>org.wso2.is.swamedia.CustomPasswordGrantTypeValidator</GrantTypeValidatorImplClass>
  </SupportedGrantType>
 ```

4. Restart the server.

5. Configure the new OAuth grant type.
    * Sign in to the WSO2 Identity Server. Enter your username and password to log on to the [Management Console](https://docs.wso2.com/display/IS500/Getting+Started+with+the+Management+Console).
    * Fill in the Service Provider Name and provide a brief Description of the service provider. See [Adding a Service Provider](https://docs.wso2.com/display/IS500/Adding+a+Service+Provider) for more information.
    * Expand the OAuth/OpenID Connect Configuration and click Configure.
    * Enter a callback URL. For example, http://localhost:8080/playground2/oauth2client. 
    * Click Add.
    * The OAuth Client Key and OAuth Client Secret will now be visible.

5. Send the grant request to the /token API using a cURL command.
      * Replace clientid:clientsecret with the OAuth Client Key and OAuth Client Secret respectively and run the following sample cURL command in a new terminal window.
  
```shell
curl --user clientid:clientsecret -k -d "grant_type=password&username=admin&password=admin" 
  -H "Content-Type: application/x-www-form-urlencoded" https://localhost:9443/oauth2/token
```
