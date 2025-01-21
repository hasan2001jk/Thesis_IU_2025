# Hierarchy For All Packages

Package Hierarchies:

*   [com.cdancy.jenkins.rest](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/package-summary.html),
*   [com.cdancy.jenkins.rest.auth](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/auth/package-summary.html),
*   [com.cdancy.jenkins.rest.binders](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/binders/package-summary.html),
*   [com.cdancy.jenkins.rest.config](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/config/package-summary.html),
*   [com.cdancy.jenkins.rest.domain.common](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/domain/common/package-summary.html),
*   [com.cdancy.jenkins.rest.domain.crumb](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/domain/crumb/package-summary.html),
*   [com.cdancy.jenkins.rest.domain.job](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/domain/job/package-summary.html),
*   [com.cdancy.jenkins.rest.domain.plugins](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/domain/plugins/package-summary.html),
*   [com.cdancy.jenkins.rest.domain.queue](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/domain/queue/package-summary.html),
*   [com.cdancy.jenkins.rest.domain.statistics](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/domain/statistics/package-summary.html),
*   [com.cdancy.jenkins.rest.domain.system](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/domain/system/package-summary.html),
*   [com.cdancy.jenkins.rest.exception](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/exception/package-summary.html),
*   [com.cdancy.jenkins.rest.fallbacks](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/fallbacks/package-summary.html),
*   [com.cdancy.jenkins.rest.features](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/features/package-summary.html),
*   [com.cdancy.jenkins.rest.filters](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/filters/package-summary.html),
*   [com.cdancy.jenkins.rest.handlers](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/handlers/package-summary.html),
*   [com.cdancy.jenkins.rest.parsers](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/parsers/package-summary.html)

## Class Hierarchy

*   java.lang.Object
    *   com.google.inject.AbstractModule (implements com.google.inject.Module)
        *   com.cdancy.jenkins.rest.config.[JenkinsAuthenticationModule](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/config/JenkinsAuthenticationModule.html)
        *   org.jclouds.rest.config.RestModule
            *   org.jclouds.rest.config.HttpApiModule<A>
                *   com.cdancy.jenkins.rest.config.[JenkinsHttpApiModule](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/config/JenkinsHttpApiModule.html)
    *   com.cdancy.jenkins.rest.domain.job.[Action](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/domain/job/Action.html)
    *   com.cdancy.jenkins.rest.domain.job.[Artifact](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/domain/job/Artifact.html)
    *   org.jclouds.apis.internal.BaseApiMetadata (implements org.jclouds.apis.ApiMetadata)
        *   org.jclouds.rest.internal.BaseHttpApiMetadata<A> (implements org.jclouds.rest.HttpApiMetadata<A>)
            *   com.cdancy.jenkins.rest.[JenkinsApiMetadata](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/JenkinsApiMetadata.html)
    *   org.jclouds.apis.internal.BaseApiMetadata.Builder<T> (implements org.jclouds.apis.ApiMetadata.Builder<B>)
        *   org.jclouds.rest.internal.BaseHttpApiMetadata.Builder<A,T> (implements org.jclouds.rest.HttpApiMetadata.Builder<A,T>)
            *   com.cdancy.jenkins.rest.[JenkinsApiMetadata.Builder](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/JenkinsApiMetadata.Builder.html)
    *   com.cdancy.jenkins.rest.binders.[BindMapToForm](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/binders/BindMapToForm.html) (implements org.jclouds.rest.Binder)
    *   com.cdancy.jenkins.rest.domain.job.[BuildInfo](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/domain/job/BuildInfo.html)
    *   com.cdancy.jenkins.rest.parsers.[BuildNumberToInteger](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/parsers/BuildNumberToInteger.html) (implements com.google.common.base.Function<F,T>)
    *   com.cdancy.jenkins.rest.domain.job.[Cause](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/domain/job/Cause.html)
    *   org.jclouds.domain.Credentials
        *   com.cdancy.jenkins.rest.[JenkinsAuthentication](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/JenkinsAuthentication.html)
    *   com.cdancy.jenkins.rest.domain.crumb.[Crumb](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/domain/crumb/Crumb.html) (implements com.cdancy.jenkins.rest.domain.common.[ErrorsHolder](com/cdancy/jenkins/rest/domain/common/ErrorsHolder.html "interface in com.cdancy.jenkins.rest.domain.common"))
    *   com.cdancy.jenkins.rest.parsers.[CrumbParser](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/parsers/CrumbParser.html) (implements com.google.common.base.Function<F,T>)
    *   com.cdancy.jenkins.rest.domain.job.[Culprit](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/domain/job/Culprit.html)
    *   com.cdancy.jenkins.rest.domain.common.[Error](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/domain/common/Error.html)
    *   com.cdancy.jenkins.rest.domain.queue.[Executable](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/domain/queue/Executable.html)
    *   com.cdancy.jenkins.rest.parsers.[FolderPathParser](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/parsers/FolderPathParser.html) (implements com.google.common.base.Function<F,T>)
    *   com.cdancy.jenkins.rest.domain.common.[IntegerResponse](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/domain/common/IntegerResponse.html) (implements com.cdancy.jenkins.rest.domain.common.[ErrorsHolder](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/domain/common/ErrorsHolder.html), com.cdancy.jenkins.rest.domain.common.[Value](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/domain/common/Value.html)<T>)
    *   com.cdancy.jenkins.rest.[JenkinsAuthentication.Builder](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/JenkinsAuthentication.Builder.html)
    *   com.cdancy.jenkins.rest.filters.[JenkinsAuthenticationFilter](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/filters/JenkinsAuthenticationFilter.html) (implements org.jclouds.http.HttpRequestFilter)
    *   com.cdancy.jenkins.rest.config.[JenkinsAuthenticationProvider](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/config/JenkinsAuthenticationProvider.html) (implements com.google.inject.Provider<T>)
    *   com.cdancy.jenkins.rest.[JenkinsClient](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/JenkinsClient.html) (implements java.io.Closeable)
    *   com.cdancy.jenkins.rest.[JenkinsClient.Builder](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/JenkinsClient.Builder.html)
    *   com.cdancy.jenkins.rest.[JenkinsConstants](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/JenkinsConstants.html)
    *   com.cdancy.jenkins.rest.handlers.[JenkinsErrorHandler](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/handlers/JenkinsErrorHandler.html) (implements org.jclouds.http.HttpErrorHandler)
    *   com.cdancy.jenkins.rest.fallbacks.[JenkinsFallbacks](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/fallbacks/JenkinsFallbacks.html)
    *   com.cdancy.jenkins.rest.fallbacks.[JenkinsFallbacks.CrumbOnError](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/fallbacks/JenkinsFallbacks.CrumbOnError.html) (implements org.jclouds.Fallback<V>)
    *   com.cdancy.jenkins.rest.fallbacks.[JenkinsFallbacks.IntegerResponseOnError](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/fallbacks/JenkinsFallbacks.IntegerResponseOnError.html) (implements org.jclouds.Fallback<V>)
    *   com.cdancy.jenkins.rest.fallbacks.[JenkinsFallbacks.JENKINS\_21311](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/fallbacks/JenkinsFallbacks.JENKINS_21311.html) (implements org.jclouds.Fallback<V>)
    *   com.cdancy.jenkins.rest.fallbacks.[JenkinsFallbacks.PluginsOnError](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/fallbacks/JenkinsFallbacks.PluginsOnError.html) (implements org.jclouds.Fallback<V>)
    *   com.cdancy.jenkins.rest.fallbacks.[JenkinsFallbacks.RequestStatusOnError](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/fallbacks/JenkinsFallbacks.RequestStatusOnError.html) (implements org.jclouds.Fallback<V>)
    *   com.cdancy.jenkins.rest.fallbacks.[JenkinsFallbacks.SystemInfoOnError](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/fallbacks/JenkinsFallbacks.SystemInfoOnError.html) (implements org.jclouds.Fallback<V>)
    *   com.cdancy.jenkins.rest.filters.[JenkinsNoCrumbAuthenticationFilter](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/filters/JenkinsNoCrumbAuthenticationFilter.html) (implements org.jclouds.http.HttpRequestFilter)
    *   com.cdancy.jenkins.rest.[JenkinsUtils](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/JenkinsUtils.html)
    *   com.cdancy.jenkins.rest.domain.job.[Job](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/domain/job/Job.html)
    *   com.cdancy.jenkins.rest.domain.job.[JobInfo](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/domain/job/JobInfo.html)
    *   com.cdancy.jenkins.rest.domain.job.[JobList](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/domain/job/JobList.html)
    *   com.cdancy.jenkins.rest.parsers.[LocationToQueueId](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/parsers/LocationToQueueId.html) (implements com.google.common.base.Function<F,T>)
    *   com.cdancy.jenkins.rest.parsers.[OptionalFolderPathParser](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/parsers/OptionalFolderPathParser.html) (implements com.google.common.base.Function<F,T>)
    *   com.cdancy.jenkins.rest.parsers.[OutputToProgressiveText](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/parsers/OutputToProgressiveText.html) (implements com.google.common.base.Function<F,T>)
    *   com.cdancy.jenkins.rest.domain.statistics.[OverallLoad](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/domain/statistics/OverallLoad.html)
    *   com.cdancy.jenkins.rest.domain.job.[Parameter](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/domain/job/Parameter.html)
    *   com.cdancy.jenkins.rest.domain.job.[PipelineNode](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/domain/job/PipelineNode.html)
    *   com.cdancy.jenkins.rest.domain.plugins.[Plugin](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/domain/plugins/Plugin.html)
    *   com.cdancy.jenkins.rest.domain.plugins.[Plugins](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/domain/plugins/Plugins.html) (implements com.cdancy.jenkins.rest.domain.common.[ErrorsHolder](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/domain/common/ErrorsHolder.html))
    *   com.cdancy.jenkins.rest.domain.job.[ProgressiveText](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/domain/job/ProgressiveText.html)
    *   com.cdancy.jenkins.rest.domain.queue.[QueueItem](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/domain/queue/QueueItem.html)
    *   com.cdancy.jenkins.rest.domain.common.[RequestStatus](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/domain/common/RequestStatus.html) (implements com.cdancy.jenkins.rest.domain.common.[ErrorsHolder](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/domain/common/ErrorsHolder.html), com.cdancy.jenkins.rest.domain.common.[Value](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/domain/common/Value.html)<T>)
    *   com.cdancy.jenkins.rest.parsers.[RequestStatusParser](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/parsers/RequestStatusParser.html) (implements com.google.common.base.Function<F,T>)
    *   com.cdancy.jenkins.rest.filters.[ScrubNullFolderParam](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/filters/ScrubNullFolderParam.html) (implements org.jclouds.http.HttpRequestFilter)
    *   com.cdancy.jenkins.rest.domain.job.[Stage](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/domain/job/Stage.html)
    *   com.cdancy.jenkins.rest.domain.job.[StageFlowNode](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/domain/job/StageFlowNode.html)
    *   com.cdancy.jenkins.rest.domain.system.[SystemInfo](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/domain/system/SystemInfo.html) (implements com.cdancy.jenkins.rest.domain.common.[ErrorsHolder](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/domain/common/ErrorsHolder.html))
    *   com.cdancy.jenkins.rest.parsers.[SystemInfoFromJenkinsHeaders](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/parsers/SystemInfoFromJenkinsHeaders.html) (implements com.google.common.base.Function<F,T>)
    *   com.cdancy.jenkins.rest.domain.queue.[Task](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/domain/queue/Task.html)
    *   java.lang.Throwable (implements java.io.Serializable)
        *   java.lang.Exception
            *   java.lang.RuntimeException
                *   com.cdancy.jenkins.rest.exception.[ForbiddenException](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/exception/ForbiddenException.html)
                *   com.cdancy.jenkins.rest.exception.[MethodNotAllowedException](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/exception/MethodNotAllowedException.html)
                *   com.cdancy.jenkins.rest.exception.[UnsupportedMediaTypeException](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/exception/UnsupportedMediaTypeException.html)
    *   com.cdancy.jenkins.rest.domain.job.[Workflow](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/domain/job/Workflow.html)

## Interface Hierarchy

*   java.lang.AutoCloseable
    *   java.io.Closeable
        *   com.cdancy.jenkins.rest.[JenkinsApi](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/JenkinsApi.html)
*   com.cdancy.jenkins.rest.features.[CrumbIssuerApi](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/features/CrumbIssuerApi.html)
*   com.cdancy.jenkins.rest.domain.common.[ErrorsHolder](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/domain/common/ErrorsHolder.html)
*   com.cdancy.jenkins.rest.features.[JobsApi](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/features/JobsApi.html)
*   com.cdancy.jenkins.rest.features.[PluginManagerApi](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/features/PluginManagerApi.html)
*   com.cdancy.jenkins.rest.features.[QueueApi](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/features/QueueApi.html)
*   com.cdancy.jenkins.rest.features.[StatisticsApi](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/features/StatisticsApi.html)
*   com.cdancy.jenkins.rest.features.[SystemApi](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/features/SystemApi.html)
*   com.cdancy.jenkins.rest.domain.common.[Value](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/domain/common/Value.html)<T>

## Enum Hierarchy

*   java.lang.Object
    *   java.lang.Enum<E> (implements java.lang.Comparable<T>, java.io.Serializable)
        *   com.cdancy.jenkins.rest.auth.[AuthenticationType](https://cdancy.github.io/jenkins-rest/docs/javadoc/com/cdancy/jenkins/rest/auth/AuthenticationType.html)
		
---

# com.cdancy.jenkins.rest

## Interface JenkinsApi



    public interface JenkinsApi extends Closeable {
    
        @Delegate
        CrumbIssuerApi crumbIssuerApi();
    
        @Delegate
        JobsApi jobsApi();
    
        @Delegate
        PluginManagerApi pluginManagerApi();
    
        @Delegate
        QueueApi queueApi();
    
        @Delegate
        StatisticsApi statisticsApi();
    
        @Delegate
        SystemApi systemApi();
    
        @Delegate
        ConfigurationAsCodeApi configurationAsCodeApi();
    
        @Delegate
        UserApi userApi();
    }
	
---

com.cdancy.jenkins.rest


    @AutoService(ApiMetadata.class)
    public class JenkinsApiMetadata extends BaseHttpApiMetadata<JenkinsApi> {
    
        public static final String API_VERSION = "1.0";
        public static final String BUILD_VERSION = "2.0";
    
        @Override
        public Builder toBuilder() {
            return new Builder().fromApiMetadata(this);
        }
    
        public JenkinsApiMetadata() {
            this(new Builder());
        }
    
        protected JenkinsApiMetadata(Builder builder) {
            super(builder);
        }
    
        public static Properties defaultProperties() {
            return BaseHttpApiMetadata.defaultProperties();
        }
    
        public static class Builder extends BaseHttpApiMetadata.Builder<JenkinsApi, Builder> {
    
            protected Builder() {
               super(JenkinsApi.class);
               id("jenkins").name("Jenkins API").identityName("Optional Username").credentialName("Optional Password")
                    .defaultIdentity("").defaultCredential("")
                    .documentation(URI.create("http://wiki.jenkins-ci.org/display/JENKINS/Remote+access+API"))
                    .version(API_VERSION).buildVersion(BUILD_VERSION).defaultEndpoint("http://127.0.0.1:8080")
                    .defaultProperties(JenkinsApiMetadata.defaultProperties())
                    .defaultModules(ImmutableSet.of(JenkinsHttpApiModule.class));
            }
    
            @Override
            public JenkinsApiMetadata build() {
                return new JenkinsApiMetadata(this);
            }
    
            @Override
            protected Builder self() {
                return this;
            }
    
            @Override
            public Builder fromApiMetadata(ApiMetadata in) {
                return this;
            }
        }
    }
	
---


## Class JenkinsApiMetadata.Builder

        public static class Builder extends BaseHttpApiMetadata.Builder<JenkinsApi, Builder> {
    
            protected Builder() {
               super(JenkinsApi.class);
               id("jenkins").name("Jenkins API").identityName("Optional Username").credentialName("Optional Password")
                    .defaultIdentity("").defaultCredential("")
                    .documentation(URI.create("http://wiki.jenkins-ci.org/display/JENKINS/Remote+access+API"))
                    .version(API_VERSION).buildVersion(BUILD_VERSION).defaultEndpoint("http://127.0.0.1:8080")
                    .defaultProperties(JenkinsApiMetadata.defaultProperties())
                    .defaultModules(ImmutableSet.of(JenkinsHttpApiModule.class));
            }
    
            @Override
            public JenkinsApiMetadata build() {
                return new JenkinsApiMetadata(this);
            }
    
            @Override
            protected Builder self() {
                return this;
            }
    
            @Override
            public Builder fromApiMetadata(ApiMetadata in) {
                return this;
            }
        }
		
---


## Class JenkinsAuthentication

    
    /**
     * Credentials instance for Jenkins authentication.
     */
    public class JenkinsAuthentication extends Credentials {
    
        private final AuthenticationType authType;
    
        /**
         * Create instance of JenkinsAuthentication.
         *
         * @param identity the identity of the credential, this would be the username for the password or the api token or the base64 encoded value.
         * @param credential the username:password, or the username:apiToken, or their base64 encoded value. This is base64 encoded before being stored.
         * @param authType authentication type (e.g. UsernamePassword, UsernameApiToken, Anonymous).
         */
        private JenkinsAuthentication(final String identity, final String credential, final AuthenticationType authType) {
            super(identity,  credential.contains(":") ? base64().encode(credential.getBytes()) : credential);
            this.authType = authType;
        }
    
        /**
         * Return the base64 encoded value of the credential.
         *
         * @return the base 64 encoded authentication value.
         */
        @Nullable
        public String authValue() {
            return this.credential;
        }
    
        /**
         * Return the authentication type.
         *
         * @return the authentication type.
         */
        public AuthenticationType authType() {
            return authType;
        }
    
        public static Builder builder() {
            return new Builder();
        }
    
        public static class Builder {
    
            private String identity = "anonymous";
            private String credential = identity + ":";
            private AuthenticationType authType = AuthenticationType.Anonymous;
    
            /**
             * Set 'UsernamePassword' credentials.
             *
             * @param usernamePassword value to use for 'UsernamePassword' credentials. It can be the {@code username:password} in clear text or its base64 encoded value.
             * @return this Builder.
             */
            public Builder credentials(final String usernamePassword) {
                this.identity = Objects.requireNonNull(extractIdentity(usernamePassword));
                this.credential = Objects.requireNonNull(usernamePassword);
                this.authType = AuthenticationType.UsernamePassword;
                return this;
            }
    
            /**
             * Set 'UsernameApiToken' credentials.
             *
             * @param apiTokenCredentials value to use for 'ApiToken' credentials. It can be the {@code username:apiToken} in clear text or its base64 encoded value.
             * @return this Builder.
             */
            public Builder apiToken(final String apiTokenCredentials) {
                this.identity = Objects.requireNonNull(extractIdentity(apiTokenCredentials));
                this.credential = Objects.requireNonNull(apiTokenCredentials);
                this.authType = AuthenticationType.UsernameApiToken;
                return this;
            }
    
            /**
             * Extract the identity from the credential.
             *
             * The credential is entered by the user in one of two forms:
             * <ol>
             *  <li>Colon separated form: <code>username:password</code> or <code>username:password</code>
             *  <li>Base64 encoded of the colon separated form.
             * </ol>
             * Either way the identity is the username, and it can be extracted directly or by decoding.
             */
            private String extractIdentity(final String credentialString) {
                String decoded;
                if (!credentialString.contains(":")) {
                    decoded = new String(base64().decode(credentialString),StandardCharsets.UTF_8);
                } else {
                    decoded = credentialString;
                }
                if (!decoded.contains(":")) {
                    throw new UndetectableIdentityException("Unable to detect the identity being used in '" + credentialString + "'. Supported types are a user:password, or a user:apiToken, or their base64 encoded value.");
                }
                if (decoded.equals(":")) {
                    return "";
                }
                return decoded.split(":")[0];
            }
    
           /**
             * Build and instance of JenkinsCredentials.
             *
             * @return instance of JenkinsCredentials.
             */
            public JenkinsAuthentication build() {
                return new JenkinsAuthentication(identity, credential, authType);
            }
        }
    }
    
---

## Class JenkinsClient



    public final class JenkinsClient implements Closeable {
    
        private final String endPoint;
        private final JenkinsAuthentication credentials;
        private final JenkinsApi jenkinsApi;
        private final Properties overrides;
    
        /**
         * Create a JenkinsClient inferring endpoint and authentication from
         * environment and system properties.
         */
        public JenkinsClient() {
            this(null, null, null, null);
        }
    
        /**
         * Create an JenkinsClient. If any of the passed in variables are null we
         * will query System Properties and Environment Variables, in order, to
         * search for values that may be set in a devops/CI fashion. The only
         * difference is the `overrides` which gets merged, but takes precedence,
         * with those System Properties and Environment Variables found.
         *
         * @param endPoint URL of Jenkins instance.
         * @param authentication authentication used to connect to Jenkins instance.
         * @param overrides jclouds Properties to override defaults when creating a new JenkinsApi.
         * @param modules a list of modules to be passed to the Contextbuilder, e.g. for logging.
         */
        public JenkinsClient(@Nullable final String endPoint,
                @Nullable final JenkinsAuthentication authentication,
                @Nullable final Properties overrides,
                @Nullable final List<Module> modules) {
            this.endPoint = endPoint != null
                    ? endPoint
                    : JenkinsUtils.inferEndpoint();
            this.credentials = authentication != null
                    ? authentication
                    : JenkinsUtils.inferAuthentication();
            this.overrides = mergeOverrides(overrides);
            this.jenkinsApi = createApi(this.endPoint, this.credentials, this.overrides, modules);
        }
    
        private JenkinsApi createApi(final String endPoint, final JenkinsAuthentication authentication, final Properties overrides, final List<Module> modules) {
            final List<Module> allModules = Lists.newArrayList(new JenkinsAuthenticationModule(authentication));
            if (modules != null) {
                allModules.addAll(modules);
            }
            return ContextBuilder
                    .newBuilder(new JenkinsApiMetadata.Builder().build())
                    .endpoint(endPoint)
                    .modules(allModules)
                    .overrides(overrides)
                    .buildApi(JenkinsApi.class);
        }
    
        /**
         * Query System Properties and Environment Variables for overrides and merge
         * the potentially passed in overrides with those.
         *
         * @param possibleOverrides Optional passed in overrides.
         * @return Properties object.
         */
        private Properties mergeOverrides(final Properties possibleOverrides) {
            final Properties inferOverrides = JenkinsUtils.inferOverrides();
            if (possibleOverrides != null) {
                inferOverrides.putAll(possibleOverrides);
            }
            return inferOverrides;
        }
    
        public String endPoint() {
            return this.endPoint;
        }
    
        @Deprecated
        public String credentials() {
            return this.authValue();
        }
    
        public Properties overrides() {
            return this.overrides;
        }
    
        public String authValue() {
            return this.credentials.authValue();
        }
    
        public AuthenticationType authType() {
            return this.credentials.authType();
        }
    
        public JenkinsApi api() {
            return this.jenkinsApi;
        }
    
        public static Builder builder() {
            return new Builder();
        }
    
        @Override
        public void close() throws IOException {
            if (this.api() != null) {
                this.api().close();
            }
        }
    
        public static class Builder {
    
            private String endPoint;
            private JenkinsAuthentication.Builder authBuilder;
            private Properties overrides;
            private List<Module> modules = Lists.newArrayList();
    
            /**
             * Define the base endpoint to connect to.
             *
             * @param endPoint Jenkins base endpoint.
             * @return this Builder.
             */
            public Builder endPoint(final String endPoint) {
                this.endPoint = endPoint;
                return this;
            }
    
            /**
             * Optional credentials to use for authentication. Must take the form of
             * `username:password` or its base64 encoded version.
             *
             * @param optionallyBase64EncodedCredentials authentication credentials.
             * @return this Builder.
             */
            public Builder credentials(final String optionallyBase64EncodedCredentials) {
                authBuilder = JenkinsAuthentication.builder()
                        .credentials(optionallyBase64EncodedCredentials);
                return this;
            }
    
            /**
             * Optional Api token to use for authentication.
             * This is not a Bearer token, hence the name apiToken.
             *
             * @param apiToken authentication token.
             * @return this Builder.
             */
            public Builder apiToken(final String apiToken) {
                authBuilder = JenkinsAuthentication.builder()
                        .apiToken(apiToken);
                return this;
            }
    
            /**
             * Optional jclouds Properties to override. What can be overridden can
             * be found here:
             *
             * <p>https://github.com/jclouds/jclouds/blob/master/core/src/main/java/org/jclouds/Constants.java
             *
             * @param overrides optional jclouds Properties to override.
             * @return this Builder.
             */
            public Builder overrides(final Properties overrides) {
                this.overrides = overrides;
                return this;
            }
    
            /**
             * Optional List of Module to add. Modules can be added, for logging
             * for example.
             *
             * @param modules optional List of Module to add.
             * @return this Builder.
             */
            public Builder modules(final Module... modules) {
                this.modules.addAll(Arrays.asList(modules));
                return this;
            }
    
            /**
             * Build an instance of JenkinsClient.
             *
             * @return JenkinsClient
             */
            public JenkinsClient build() {
    
                // 1.) If user passed in some auth use/build that.
                final JenkinsAuthentication authentication = authBuilder != null
                        ? authBuilder.build()
                        : null;
    
                return new JenkinsClient(endPoint, authentication, overrides, modules);
            }
        }
    }
    
---

## Class JenkinsConstants



    
    /**
     * Various constants that can be used in a global context.
     */
    public class JenkinsConstants {
    
        public static final String ENDPOINT_SYSTEM_PROPERTY = "jenkins.rest.endpoint";
        public static final String ENDPOINT_ENVIRONMENT_VARIABLE = ENDPOINT_SYSTEM_PROPERTY.replaceAll("\\.", "_").toUpperCase();
    
        public static final String CREDENTIALS_SYSTEM_PROPERTY = "jenkins.rest.credentials";
        public static final String CREDENTIALS_ENVIRONMENT_VARIABLE = CREDENTIALS_SYSTEM_PROPERTY.replaceAll("\\.", "_").toUpperCase();
    
        public static final String API_TOKEN_SYSTEM_PROPERTY = "jenkins.rest.api.token";
        public static final String API_TOKEN_ENVIRONMENT_VARIABLE = API_TOKEN_SYSTEM_PROPERTY.replaceAll("\\.", "_").toUpperCase();
    
        public static final String DEFAULT_ENDPOINT = "http://127.0.0.1:7990";
    
        public static final String JCLOUDS_PROPERTY_ID = "jclouds.";
        public static final String JENKINS_REST_PROPERTY_ID = "jenkins.rest." + JCLOUDS_PROPERTY_ID;
    
        public static final String JCLOUDS_VARIABLE_ID = "JCLOUDS_";
        public static final String JENKINS_REST_VARIABLE_ID = "JENKINS_REST_" + JCLOUDS_VARIABLE_ID;
    
        public static final String OPTIONAL_FOLDER_PATH_PARAM = "optionalFolderPath";
    
        public static final String USER_IN_USER_API = "user";
    
        public static final String JENKINS_COOKIES_JSESSIONID = "JSESSIONID";
    
        protected JenkinsConstants() {
            throw new UnsupportedOperationException("Purposefully not implemented");
        }
    }
    
---

## Class JenkinsUtils



    
    /**
     * Collection of static methods to be used globally.
     */
    @SuppressWarnings("PMD.TooManyStaticImports")
    public class JenkinsUtils {
    
        // global gson parser object
        public static final Gson GSON_PARSER = new Gson();
        public static final JsonParser JSON_PARSER = new JsonParser();
    
        /**
         * Convert passed Iterable into an ImmutableList.
         *
         * @param <T> an arbitrary type.
         * @param input the Iterable to copy.
         * @return ImmutableList or empty ImmutableList if `input` is null.
         */
        public static <T> List<T> nullToEmpty(final Iterable<? extends T> input) {
            return input == null ? ImmutableList.of() : ImmutableList.copyOf(input);
        }
    
        /**
         * Convert passed Map into an ImmutableMap.
         *
         * @param <K> an arbitrary type.
         * @param <V> an arbitrary type.
         * @param input the Map to copy.
         * @return ImmutableMap or empty ImmutableMap if `input` is null.
         */
        public static <K, V> Map<K, V> nullToEmpty(final Map<? extends K, ? extends V> input) {
            return input == null ? ImmutableMap.of() : ImmutableMap.copyOf(input);
        }
    
        /**
         * Convert passed Map into a JsonElement.
         *
         * @param input the Map to convert.
         * @return JsonElement or empty JsonElement if `input` is null.
         */
        public static JsonElement nullToJsonElement(final Map input) {
            return GSON_PARSER.toJsonTree(nullToEmpty(input));
        }
    
        /**
         * Convert passed Map into a JsonElement.
         *
         * @param input the Map to convert.
         * @return JsonElement or empty JsonElement if `input` is null.
         */
        public static JsonElement nullToJsonElement(final JsonElement input) {
            return input != null ? input : GSON_PARSER.toJsonTree(ImmutableMap.of());
        }
    
        /**
         * Convert passed String into a JsonElement.
         *
         * @param input the String to convert.
         * @return JsonElement or empty JsonElement if `input` is null.
         */
        public static JsonElement nullToJsonElement(final String input) {
            return JSON_PARSER.parse(input != null ? input : "{}");
        }
    
        /**
         * If the passed systemProperty is non-null we will attempt to query
         * the `System Properties` for a value and return it. If no value
         * was found, and environmentVariable is non-null, we will attempt to
         * query the `Environment Variables` for a value and return it. If
         * both are either null or can't be found than null will be returned.
         *
         * @param systemProperty possibly existent System Property.
         * @param environmentVariable possibly existent Environment Variable.
         * @return found external value or null.
         */
        public static String retriveExternalValue(@Nullable final String systemProperty,
                @Nullable final String environmentVariable) {
    
            // 1.) Search for System Property
            if (systemProperty != null) {
                final String value = System.getProperty(systemProperty);
                if (value != null) {
                    return value;
                }
            }
    
            if (environmentVariable != null) {
                final String value = System.getenv().get(environmentVariable);
                if (value != null) {
                    return value;
                }
            }
    
            return null;
        }
    
        /**
         * Find endpoint searching first within `System Properties` and
         * then within `Environment Variables` returning whichever has a
         * value first.
         *
         * @return endpoint or null if it can't be found.
         */
        public static String inferEndpoint() {
            final String possibleValue = JenkinsUtils
                    .retriveExternalValue(ENDPOINT_SYSTEM_PROPERTY,
                            ENDPOINT_ENVIRONMENT_VARIABLE);
            return possibleValue != null ? possibleValue : DEFAULT_ENDPOINT;
        }
    
        /**
         * Find credentials (ApiToken, UsernamePassword, or Anonymous) from system/environment.
         *
         * @return JenkinsAuthentication
         */
        public static JenkinsAuthentication inferAuthentication() {
    
            final JenkinsAuthentication.Builder inferAuth = JenkinsAuthentication.builder();
            // 1.) Check for API Token as this requires no crumb hence is faster
            String authValue = JenkinsUtils
                    .retriveExternalValue(API_TOKEN_SYSTEM_PROPERTY,
                            API_TOKEN_ENVIRONMENT_VARIABLE);
            if (authValue != null) {
                inferAuth.apiToken(authValue);
                return inferAuth.build();
            }
    
            // 2.) Check for UsernamePassword auth credentials.
            authValue = JenkinsUtils
                    .retriveExternalValue(CREDENTIALS_SYSTEM_PROPERTY,
                            CREDENTIALS_ENVIRONMENT_VARIABLE);
            if (authValue != null) {
                inferAuth.credentials(authValue);
                return inferAuth.build();
            }
    
            // 3.) If neither #1 or #2 find anything "Anonymous" access is assumed.
            return inferAuth.build();
        }
    
        /**
         * Find jclouds overrides (e.g. Properties) first searching within System
         * Properties and then within Environment Variables (former takes precedance).
         *
         * @return Properties object with populated jclouds properties.
         */
        public static Properties inferOverrides() {
            final Properties overrides = new Properties();
    
            // 1.) Iterate over system properties looking for relevant properties.
            final Properties systemProperties = System.getProperties();
            final Enumeration<String> enums = (Enumeration<String>) systemProperties.propertyNames();
            while (enums.hasMoreElements()) {
                final String key = enums.nextElement();
                if (key.startsWith(JENKINS_REST_PROPERTY_ID)) {
                    final int index = key.indexOf(JCLOUDS_PROPERTY_ID);
                    final String trimmedKey = key.substring(index, key.length());
                    overrides.put(trimmedKey, systemProperties.getProperty(key));
                }
            }
    
            // 2.) Iterate over environment variables looking for relevant variables. System
            //     Properties take precedence here so if the same property was already found
            //     there then we don't add it or attempt to override.
            for (final Map.Entry<String, String> entry : System.getenv().entrySet()) {
                if (entry.getKey().startsWith(JENKINS_REST_VARIABLE_ID)) {
                    final int index = entry.getKey().indexOf(JCLOUDS_VARIABLE_ID);
                    final String trimmedKey = entry.getKey()
                            .substring(index, entry.getKey().length())
                            .toLowerCase()
                            .replaceAll("_", ".");
                    if (!overrides.containsKey(trimmedKey)) {
                        overrides.put(trimmedKey, entry.getValue());
                    }
                }
            }
    
            return overrides;
        }
    
        /**
         * Add the passed environment variables to the currently existing env-vars.
         *
         * @param addEnvVars the env-vars to add.
         */
        public static void addEnvironmentVariables(final Map<String, String> addEnvVars) {
            Objects.requireNonNull(addEnvVars, "Must pass non-null Map");
            final Map<String, String> newenv = Maps.newHashMap(System.getenv());
            newenv.putAll(addEnvVars);
            setEnvironmentVariables(newenv);
        }
    
        /**
         * Remove the passed environment variables keys from the environment.
         *
         * @param removeEnvVars the env-var keys to be removed.
         */
        public static void removeEnvironmentVariables(final Collection<String> removeEnvVars) {
            Objects.requireNonNull(removeEnvVars, "Must pass non-null Collection");
            final Map<String, String> newenv = Maps.newHashMap(System.getenv());
            newenv.keySet().removeAll(removeEnvVars);
            setEnvironmentVariables(newenv);
        }
    
        /**
         * Re-set the environment variables with passed map.
         *
         * @param newEnvVars map to reset env-vars with.
         */
        public static void setEnvironmentVariables(final Map<String, String> newEnvVars) {
            Objects.requireNonNull(newEnvVars, "Must pass non-null Map");
    
            try {
                final Class<?> processEnvironmentClass = Class.forName("java.lang.ProcessEnvironment");
                final Field theEnvironmentField = processEnvironmentClass.getDeclaredField("theEnvironment");
                theEnvironmentField.setAccessible(true);
                final Map<String, String> env = (Map<String, String>) theEnvironmentField.get(null);
                env.putAll(newEnvVars);
                final Field theCaseInsensitiveEnvironmentField = processEnvironmentClass.getDeclaredField("theCaseInsensitiveEnvironment");
                theCaseInsensitiveEnvironmentField.setAccessible(true);
                final Map<String, String> cienv = (Map<String, String>) theCaseInsensitiveEnvironmentField.get(null);
                cienv.putAll(newEnvVars);
            } catch (final ClassNotFoundException | IllegalAccessException | IllegalArgumentException | NoSuchFieldException | SecurityException e) {
                final Class[] classes = Collections.class.getDeclaredClasses();
                final Map<String, String> env = System.getenv();
                for (final Class cl : classes) {
                    if ("java.util.Collections$UnmodifiableMap".equals(cl.getName())) {
                        try {
                            final Field field = cl.getDeclaredField("m");
                            field.setAccessible(true);
                            final Object obj = field.get(env);
                            final Map<String, String> map = (Map<String, String>) obj;
                            map.clear();
                            map.putAll(newEnvVars);
                        } catch (final NoSuchFieldException | IllegalAccessException e2) {
                            throw Throwables.propagate(e2);
                        }
                    }
                }
            }
        }
    
        protected JenkinsUtils() {
            throw new UnsupportedOperationException("Purposefully not implemented");
        }
    }
    
---

# com.cdancy.jenkins.rest.auth

## Enum AuthenticationType



    
    /**
     * Supported Authentication Types for Jenkins.
     */
    public enum AuthenticationType {
    
        UsernamePassword("UsernamePassword", "Basic"),
        UsernameApiToken("UsernameApiToken", "Basic"),
        Anonymous("Anonymous", "");
    
        private final String authName;
        private final String authScheme;
    
        AuthenticationType(final String authName, final String authScheme) {
            this.authName = authName;
            this.authScheme = authScheme;
        }
    
        public String getAuthScheme() {
            return authScheme;
        }
    
        @Override
        public String toString() {
            return authName;
        }
    }
---
# com.cdancy.jenkins.rest.binders

## Class BindMapToForm



    
    @Singleton
    public class BindMapToForm implements Binder {
       @SuppressWarnings("unchecked")
       @Override
       public <R extends HttpRequest> R bindToRequest(final R request, final Object properties) {
    
           if (properties == null) {
               return (R) request.toBuilder().build();
           }
    
          checkArgument(properties instanceof Map, "binder is only valid for Map");
          Map<String, List<String>> props = (Map<String, List<String>>) properties;
    
          Builder<?> builder = request.toBuilder();
          for (Map.Entry<String, List<String>> prop : props.entrySet()) {
             if (prop.getKey() != null) {
                String potentialKey = prop.getKey().trim();
                if (potentialKey.length() > 0) {
                    if (prop.getValue() == null) {
                        prop.setValue(Lists.newArrayList(""));
                    }
    
                    builder.addFormParam(potentialKey, prop.getValue().toArray(new String[prop.getValue().size()]));
                }
             }
          }
    
          return (R) builder.build();
       }
    }
    
---

# Package com.cdancy.jenkins.rest.config

## Class JenkinsAuthenticationModule

    
    /**
     * Configure the provider for JenkinsAuthentication.
     */
    public class JenkinsAuthenticationModule extends AbstractModule {
    
        private final JenkinsAuthentication authentication;
    
        public JenkinsAuthenticationModule(final JenkinsAuthentication authentication) {
            this.authentication = Objects.requireNonNull(authentication);
        }
    
        @Override
        protected void configure() {
            bind(JenkinsAuthentication.class).toProvider(new JenkinsAuthenticationProvider(authentication));
        }
    }
	
## Class JenkinsAuthenticationProvider


    /**
     * Provider for JenkinsAuthentication objects. The JenkinsAuthentication
     * should be created ahead of time with this module simply handing it out
     * to downstream objects for injection.
     */
    public class JenkinsAuthenticationProvider implements Provider<JenkinsAuthentication> {
    
        private final JenkinsAuthentication creds;
    
        @Inject
        public JenkinsAuthenticationProvider(final JenkinsAuthentication creds) {
            this.creds = creds;
        }
    
        @Override
        public JenkinsAuthentication get() {
            return creds;
        }
    }
	
## Class JenkinsHttpApiModule



    @ConfiguresHttpApi
    public class JenkinsHttpApiModule extends HttpApiModule<JenkinsApi> {
    
        @Override
        protected void bindErrorHandlers() {
            bind(HttpErrorHandler.class).annotatedWith(Redirection.class).to(JenkinsErrorHandler.class);
            bind(HttpErrorHandler.class).annotatedWith(ClientError.class).to(JenkinsErrorHandler.class);
            bind(HttpErrorHandler.class).annotatedWith(ServerError.class).to(JenkinsErrorHandler.class);
        }
    }
    
---

#  com.cdancy.jenkins.rest.domain.common

## Interface ErrorsHolder

    
    /**
     * This interface should NOT be applied to "option" like classes and/or used 
     * in instances where this is applied to outgoing http traffic. This interface 
     * should ONLY be used for classes modeled after incoming http traffic.
     */
    public interface ErrorsHolder {
    
        List<Error> errors();
    }
    

## Interface Value<T>

	public interface Value<T> {

		@Nullable
		public abstract T value();
	}

# Class Error


	@AutoValue
	public abstract class Error {

		@Nullable
		public abstract String context();

		@Nullable
		public abstract String message();

		public abstract String exceptionName();
		
		Error() {
		}

		@SerializedNames({ "context", "message", "exceptionName" })
		public static Error create(final String context, 
				final String message, 
				final String exceptionName) {
			
			return new AutoValue_Error(context, 
					message, 
					exceptionName);
		}
	}
	
# Class IntegerResponse



    /**
     * Integer response to be returned when an endpoint returns
     * an integer.
     * 
     * <p>When the HTTP response code is valid the `value` parameter will 
     * be set to the integer value while a non-valid response has the `value` set to
     * null along with any potential `error` objects returned from Jenkins.
     */
    @AutoValue
    public abstract class IntegerResponse implements Value<Integer>, ErrorsHolder {
        
        @SerializedNames({ "value", "errors" })
        public static IntegerResponse create(@Nullable final Integer value, 
                final List<Error> errors) {
            
            return new AutoValue_IntegerResponse(value, 
                    JenkinsUtils.nullToEmpty(errors));
        }
    }
	
# Class RequestStatus

    /**
     * Generic response to be returned when an endpoint returns 
     * no content (i.e. 204 response code).
     * 
     * <p>When the response code is valid the `value` parameter will 
     * be set to true while a non-valid response has the `value` set to
     * false along with any potential `error` objects returned from Jenkins.
     */
    @AutoValue
    public abstract class RequestStatus implements Value<Boolean>, ErrorsHolder {
        
        @SerializedNames({ "value", "errors" })
        public static RequestStatus create(@Nullable final Boolean value, 
                final List<Error> errors) {
            
            return new AutoValue_RequestStatus(value, 
                    JenkinsUtils.nullToEmpty(errors));
        }
    }
	
# com.cdancy.jenkins.rest.domain.crumb

## Class Crumb

	@AutoValue
	public abstract class Crumb implements ErrorsHolder {

		@Nullable
		public abstract String value();

		@Nullable
		public abstract String sessionIdCookie();

		@SerializedNames({ "value", "errors" })
		public static Crumb create(final String value,
				final List<Error> errors) {

			return create(value, null, errors);
		}

		@SerializedNames({ "value", "sessionIdCookie" })
		public static Crumb create(final String value, final String sessionIdCookie) {
			return create(value, sessionIdCookie, null);
		}

		private static Crumb create(final String value, final String sessionIdCookie,
				final List<Error> errors) {

			return new AutoValue_Crumb(JenkinsUtils.nullToEmpty(errors), value,
					sessionIdCookie);
		}
	}
	
# com.cdancy.jenkins.rest.domain.job

## Class Action

	@AutoValue
	public abstract class Action {

		public abstract List<Cause> causes();

		public abstract List<Parameter> parameters();

		@Nullable
		public abstract String text();

		@Nullable
		public abstract String iconPath();

		@Nullable
		public abstract String _class();
		Action() {
		}

		@SerializedNames({"causes", "parameters", "text", "iconPath", "_class"})
		public static Action create(final List<Cause> causes, final List<Parameter> parameters, final String text, final String iconPath, final String _class) {
			return new AutoValue_Action(
				causes != null ? ImmutableList.copyOf(causes) : ImmutableList.<Cause>of(),
				parameters != null ? ImmutableList.copyOf(parameters) : ImmutableList.<Parameter>of(),
				text, iconPath, _class
			);
		}
	}
	
## Class Artifact

	@AutoValue
	public abstract class Artifact {

	   @Nullable
	   public abstract String displayPath();

	   public abstract String fileName();

	   public abstract String relativePath();

	   Artifact() {
	   }

	   @SerializedNames({ "displayPath", "fileName", "relativePath" })
	   public static Artifact create(String displayPath, String fileName, String relativePath) {
		  return new AutoValue_Artifact(displayPath, fileName, relativePath);
	   }
	}
	
	
## Class BuildInfo


	@AutoValue
	public abstract class BuildInfo {

	   public abstract List<Artifact> artifacts();

	   public abstract List<Action> actions();

	   public abstract boolean building();

	   @Nullable
	   public abstract String description();

	   @Nullable
	   public abstract String displayName();

	   public abstract long duration();

	   public abstract long estimatedDuration();

	   @Nullable
	   public abstract String fullDisplayName();

	   @Nullable
	   public abstract String id();

	   public abstract boolean keepLog();

	   public abstract int number();

	   public abstract int queueId();

	   @Nullable
	   public abstract String result();

	   public abstract long timestamp();

	   @Nullable
	   public abstract String url();

	   public abstract List<ChangeSetList> changeSets();
	   
	   @Nullable
	   public abstract String builtOn();

	   public abstract List<Culprit> culprits();

	   BuildInfo() {
	   }

	   @SerializedNames({ "artifacts", "actions", "building", "description", "displayName", "duration", "estimatedDuration",
			 "fullDisplayName", "id", "keepLog", "number", "queueId", "result", "timestamp", "url", "changeSets", "builtOn", "culprits" })
	   public static BuildInfo create(List<Artifact> artifacts, List<Action> actions, boolean building, String description, String displayName,
			 long duration, long estimatedDuration, String fullDisplayName, String id, boolean keepLog, int number,
			 int queueId, String result, long timestamp, String url, List<ChangeSetList> changeSets, String builtOn, List<Culprit> culprits) {
		  return new AutoValue_BuildInfo(
				artifacts != null ? ImmutableList.copyOf(artifacts) : ImmutableList.<Artifact> of(),
				actions != null ? ImmutableList.copyOf(actions) : ImmutableList.<Action> of(),
				building, description, displayName, duration, estimatedDuration, fullDisplayName,
				id, keepLog, number, queueId, result, timestamp, url, 
				changeSets != null ? ImmutableList.copyOf(changeSets) : ImmutableList.<ChangeSetList> of(),
				builtOn,
				culprits != null ? ImmutableList.copyOf(culprits) : ImmutableList.<Culprit> of());
	   }
	}


## Class Cause

	@AutoValue
	public abstract class Cause {

		@Nullable
		public abstract String clazz();

		public abstract String shortDescription();

		@Nullable
		public abstract String userId();

		@Nullable
		public abstract String userName();

		Cause() {
		}

		@SerializedNames({"_class", "shortDescription", "userId", "userName"})
		public static Cause create(final String clazz, final String shortDescription, final String userId, final String userName) {
			return new AutoValue_Cause(clazz, shortDescription, userId, userName);
		}
	}
	

## Class Culprit

	@AutoValue
	public abstract class Culprit {

	   public abstract String absoluteUrl();

	   public abstract String fullName();

	   Culprit() {
	   }

	   @SerializedNames({ "absoluteUrl", "fullName" })
	   public static Culprit create(String absoluteUrl, String fullName) {
		  return new AutoValue_Culprit(absoluteUrl, fullName);
	   }
	}
	
## Class Job

	@AutoValue
	public abstract class Job {

		@Nullable
		public abstract String clazz();

		public abstract String name();

		public abstract String url();

		@Nullable
		public abstract String color();

		Job() {
		}

		@SerializedNames({"_class", "name", "url", "color"})
		public static Job create(final String clazz, final String name, final String url, final String color) {
			return new AutoValue_Job(clazz, name, url, color);
		}
	}
	
## Class JobInfo


	@AutoValue
	public abstract class JobInfo {

	   @Nullable
	   public abstract String description();

	   @Nullable
	   public abstract String displayName();

	   @Nullable
	   public abstract String displayNameOrNull();

	   public abstract String name();

	   public abstract String url();

	   public abstract boolean buildable();

	   public abstract List<BuildInfo> builds();

	   @Nullable
	   public abstract String color();

	   @Nullable
	   public abstract BuildInfo firstBuild();

	   public abstract boolean inQueue();

	   public abstract boolean keepDependencies();

	   @Nullable
	   public abstract BuildInfo lastBuild();

	   @Nullable
	   public abstract BuildInfo lastCompleteBuild();

	   @Nullable
	   public abstract BuildInfo lastFailedBuild();

	   @Nullable
	   public abstract BuildInfo lastStableBuild();

	   @Nullable
	   public abstract BuildInfo lastSuccessfulBuild();

	   @Nullable
	   public abstract BuildInfo lastUnstableBuild();

	   @Nullable
	   public abstract BuildInfo lastUnsuccessfulBuild();

	   public abstract int nextBuildNumber();

	   @Nullable
	   public abstract QueueItem queueItem();

	   public abstract boolean concurrentBuild();

	   JobInfo() {
	   }

	   @SerializedNames({ "description", "displayName", "displayNameOrNull", "name", "url", "buildable", "builds", "color",
			 "firstBuild", "inQueue", "keepDependencies", "lastBuild", "lastCompleteBuild", "lastFailedBuild",
			 "lastStableBuild", "lastSuccessfulBuild", "lastUnstableBuild", "lastUnsuccessfulBuild", "nextBuildNumber",
			 "queueItem", "concurrentBuild" })
	   public static JobInfo create(String description, String displayName, String displayNameOrNull, String name,
			 String url, boolean buildable, List<BuildInfo> builds, String color, BuildInfo firstBuild, boolean inQueue,
			 boolean keepDependencies, BuildInfo lastBuild, BuildInfo lastCompleteBuild, BuildInfo lastFailedBuild,
			 BuildInfo lastStableBuild, BuildInfo lastSuccessfulBuild, BuildInfo lastUnstableBuild, BuildInfo lastUnsuccessfulBuild,
			 int nextBuildNumber, QueueItem queueItem, boolean concurrentBuild) {
		  return new AutoValue_JobInfo(description, displayName, displayNameOrNull, name, url, buildable,
				builds != null ? ImmutableList.copyOf(builds) : ImmutableList.<BuildInfo> of(), color, firstBuild, inQueue,
				keepDependencies, lastBuild, lastCompleteBuild, lastFailedBuild, lastStableBuild, lastSuccessfulBuild,
				lastUnstableBuild, lastUnsuccessfulBuild, nextBuildNumber, queueItem, concurrentBuild);
	   }
	}


## Class JobList

	@AutoValue
	public abstract class JobList {

		@Nullable
		public abstract String clazz();

		public abstract List<Job> jobs();

		@Nullable
		public abstract String url();

		JobList() {
		}

		@SerializedNames({"_class", "jobs", "url"})
		public static JobList create(final String clazz, final List<Job> jobs, final String url) {
			return new AutoValue_JobList(clazz, jobs, url);
		}
	}
	
## Class Parameter

	@AutoValue
	public abstract class Parameter {

		@Nullable
		public abstract String clazz();

		public abstract String name();

		@Nullable
		public abstract String value();

		Parameter() {
		}

		@SerializedNames({"_class", "name", "value"})
		public static Parameter create(final String clazz, final String name, final String value) {
			return new AutoValue_Parameter(clazz, name, value);
		}
	}

## Class PipelineNode


	@AutoValue
	public abstract class PipelineNode {

		public abstract String name();

		public abstract String status();

		public abstract long startTimeMillis();

		public abstract long durationTimeMillis();

		public abstract List<StageFlowNode> stageFlowNodes();

		PipelineNode() {
		}

		@SerializedNames({ "name", "status", "startTimeMillis", "durationTimeMillis", "stageFlowNodes" })
		public static PipelineNode create(String name, String status, long startTimeMillis, long durationTimeMillis, List<StageFlowNode> stageFlowNodes) {
			return new AutoValue_PipelineNode(name, status, startTimeMillis, durationTimeMillis, stageFlowNodes);
		}
	}
	
	
## Class ProgressiveText

	@AutoValue
	public abstract class ProgressiveText {

	   public abstract String text();

	   public abstract int size();

	   public abstract boolean hasMoreData();

	   ProgressiveText() {
	   }

	   @SerializedNames({ "text", "size", "hasMoreData" })
	   public static ProgressiveText create(String text, int size, boolean hasMoreData) {
		  return new AutoValue_ProgressiveText(text, size, hasMoreData);
	   }
	}


## Class Stage

	@AutoValue
	public abstract class Stage {
	   public abstract String id();

	   public abstract String name();

	   public abstract String status();

	   public abstract long startTimeMillis();

	   public abstract long endTimeMillis();

	   public abstract long pauseDurationMillis();

	   public abstract long durationMillis();

	   Stage() {
	   }

	   @SerializedNames({ "id", "name", "status", "startTimeMillis", "endTimeMillis", "pauseDurationMillis", "durationMillis" })
	   public static Stage create(String id, String name, String status, long startTimeMillis, long endTimeMillis, long pauseDurationMillis, long durationMillis) {
		  return new AutoValue_Stage(id, name, status, startTimeMillis, endTimeMillis, pauseDurationMillis, durationMillis);
	   }
	}


## Class StageFlowNode

	@AutoValue
	public abstract class StageFlowNode {

	   public abstract String name();

	   public abstract String status();

	   public abstract long startTimeMillis();

	   public abstract long durationTimeMillis();

	   public abstract List<Long> parentNodes();

	   StageFlowNode() {
	   }

	   @SerializedNames({ "name", "status", "startTimeMillis", "durationTimeMillis", "parentNodes" })
	   public static StageFlowNode create(String name, String status, long startTimeMillis, long durationTimeMillis, List<Long> parentNodes) {
		  return new AutoValue_StageFlowNode(name, status, startTimeMillis, durationTimeMillis, parentNodes);
	   }
	}
	
## Class Workflow

	@AutoValue
	public abstract class Workflow {

	   public abstract String name();

	   public abstract String status();

	   public abstract long startTimeMillis();

	   public abstract long durationTimeMillis();

	   public abstract List<Stage> stages();

	   Workflow() {
	   }

	   @SerializedNames({ "name", "status", "startTimeMillis", "durationTimeMillis", "stages" })
	   public static Workflow create(String name, String status, long startTimeMillis, long durationTimeMillis, List<Stage> stages) {
		  return new AutoValue_Workflow(name, status, startTimeMillis, durationTimeMillis, stages);
	   }
	}
	

# com.cdancy.jenkins.rest.domain.plugins

## Class Plugin


	@AutoValue
	public abstract class Plugin {

		@Nullable
		public abstract Boolean active();

		@Nullable
		public abstract String backupVersion();
		
		@Nullable    
		public abstract Boolean bundled();

		@Nullable
		public abstract Boolean deleted();

		@Nullable
		public abstract Boolean downgradable();

		@Nullable
		public abstract Boolean enabled();

		@Nullable    
		public abstract Boolean hasUpdate();

		@Nullable    
		public abstract String longName();

		@Nullable    
		public abstract Boolean pinned();

		@Nullable    
		public abstract String requiredCoreVersion();

		@Nullable    
		public abstract String shortName();

		@Nullable    
		public abstract String supportsDynamicLoad();

		@Nullable    
		public abstract String url();

		@Nullable    
		public abstract String version();

		Plugin() {
		}

		@SerializedNames({ "active", "backupVersion", "bundled",
			"deleted", "downgradable", "enabled",
			"hasUpdate", "longName", "pinned", 
			"requiredCoreVersion", "shortName", "supportsDynamicLoad",
			"url", "version"})
		public static Plugin create(Boolean active, String backupVersion, Boolean bundled,
				Boolean deleted, Boolean downgradable, Boolean enabled,
				Boolean hasUpdate, String longName, Boolean pinned,
				String requiredCoreVersion, String shortName, String supportsDynamicLoad,
				String url, String version) {
			return new AutoValue_Plugin(active, backupVersion, bundled,
				deleted, downgradable, enabled,
				hasUpdate, longName, pinned,
				requiredCoreVersion, shortName, supportsDynamicLoad,
				url, version);
		}
	}


## Class Plugins

	@AutoValue
	public abstract class Plugins implements ErrorsHolder {

		@Nullable
		public abstract String clazz();
		
		public abstract List<Plugin> plugins();

		Plugins() {
		}

		@SerializedNames({ "_class", "plugins", "errors" })
		public static Plugins create(final String clazz,
				final List<Plugin> plugins,
				final List<Error> errors) {
			return new AutoValue_Plugins(JenkinsUtils.nullToEmpty(errors),
					clazz,
					JenkinsUtils.nullToEmpty(plugins));
		}
	}
	

#  com.cdancy.jenkins.rest.domain.queue

## Class Executable

	@AutoValue
	public abstract class Executable {

	   public abstract Integer number();

	   public abstract String url();

	   Executable() {
	   }

	   @SerializedNames({ "number", "url" })
	   public static Executable create(Integer number, String url) {
		  return new AutoValue_Executable(number, url);
	   }
	}
	
## Class QueueItem

	@AutoValue
	public abstract class QueueItem {

	   public abstract boolean blocked();

	   public abstract boolean buildable();

	   public abstract int id();

	   public abstract long inQueueSince();

	   public abstract Map<String, String> params();

	   public abstract boolean stuck();

	   public abstract Task task();

	   public abstract String url();

	   @Nullable
	   public abstract String why();

		// https://javadoc.jenkins.io/hudson/model/Queue.NotWaitingItem.html
		/**
		 * When did this job exit the Queue.waitingList phase?
		 * For a Queue.NotWaitingItem
		 * @return The time expressed in milliseconds after January 1, 1970, 0:00:00 GMT.
		 */
	   public abstract long buildableStartMilliseconds();

	   public abstract boolean cancelled();

	   @Nullable
	   public abstract Executable executable();

		// https://javadoc.jenkins.io/hudson/model/Queue.WaitingItem.html
		/**
		 * This item can be run after this time.
		 * For a Queue.WaitingItem
		 * @return The time expressed in milliseconds after January 1, 1970, 0:00:00 GMT.
		 */
	   @Nullable
	   public abstract Long timestamp();

	   QueueItem() {
	   }

	   @SerializedNames({ "blocked", "buildable", "id", "inQueueSince", "params", "stuck", "task", "url", "why",
			 "buildableStartMilliseconds", "cancelled", "executable", "timestamp"})
	   public static QueueItem create(boolean blocked, boolean buildable, int id, long inQueueSince, String params,
			 boolean stuck, Task task, String url, String why, long buildableStartMilliseconds,
		 boolean cancelled, Executable executable, Long timestamp) {
		  Map<String, String> parameters = Maps.newHashMap();
		  if (params != null) {
			 params = params.trim();
			 if (params.length() > 0) {
				for (String keyValue : params.split("\n")) {
				   String[] pair = keyValue.split("=");
				   parameters.put(pair[0], pair.length > 1 ? pair[1] : "");
				}
			 }
		  }
		  return new AutoValue_QueueItem(blocked, buildable, id, inQueueSince, parameters, stuck, task, url, why,
				buildableStartMilliseconds, cancelled, executable, timestamp);
	   }
	}


## Class Task

	@AutoValue
	public abstract class Task {

	   @Nullable
	   public abstract String name();

	   @Nullable
	   public abstract String url();

	   Task() {
	   }

	   @SerializedNames({ "name", "url" })
	   public static Task create(String name, String url) {
		  return new AutoValue_Task(name, url);
	   }
	}
	
	
# com.cdancy.jenkins.rest.domain.statistics

## Class OverallLoad


	@AutoValue
	public abstract class OverallLoad {

		@Nullable
		public abstract Map<String, String> availableExecutors();

		@Nullable
		public abstract Map<String, String> busyExecutors();

		@Nullable
		public abstract Map<String, String> connectingExecutors();

		@Nullable
		public abstract Map<String, String> definedExecutors();

		@Nullable
		public abstract Map<String, String> idleExecutors();

		@Nullable
		public abstract Map<String, String> onlineExecutors();

		@Nullable
		public abstract Map<String, String> queueLength();

		@Nullable
		public abstract Map<String, String> totalExecutors();

		@Nullable
		public abstract Map<String, String> totalQueueLength();

		OverallLoad() {
		}

		@SerializedNames({ "availableExecutors", "busyExecutors", "connectingExecutors", "definedExecutors", "idleExecutors",
			  "onlineExecutors", "queueLength", "totalExecutors", "totalQueueLength" })
		public static OverallLoad create(Map<String, String> availableExecutors, Map<String, String> busyExecutors,
			  Map<String, String> connectingExecutors, Map<String, String> definedExecutors,
			  Map<String, String> idleExecutors, Map<String, String> onlineExecutors, Map<String, String> queueLength,
			  Map<String, String> totalExecutors, Map<String, String> totalQueueLength) {
			return new AutoValue_OverallLoad(availableExecutors, busyExecutors,
					connectingExecutors, definedExecutors,
					idleExecutors, onlineExecutors,
					queueLength, totalExecutors,
					totalQueueLength);
		}
	}


# com.cdancy.jenkins.rest.domain.system

## Class SystemInfo

	@AutoValue
	public abstract class SystemInfo implements ErrorsHolder {

		public abstract String hudsonVersion();

		public abstract String jenkinsVersion();

		public abstract String jenkinsSession();

		public abstract String instanceIdentity();

		@Nullable
		public abstract String sshEndpoint();

		public abstract String server();

		SystemInfo() {
		}

		@SerializedNames({ "hudsonVersion", "jenkinsVersion", "jenkinsSession",
			"instanceIdentity", "sshEndpoint", "server", "errors" })
		public static SystemInfo create(String hudsonVersion, String jenkinsVersion, String jenkinsSession,
				String instanceIdentity,
				String sshEndpoint, String server, final List<Error> errors) {
			return new AutoValue_SystemInfo(JenkinsUtils.nullToEmpty(errors),
					hudsonVersion, jenkinsVersion, jenkinsSession, 
					instanceIdentity, sshEndpoint, server);
		}
	}
	
# com.cdancy.jenkins.rest.exception

## Class ForbiddenException



    /**
     * Thrown when an action has breached the licensed user limit of the server, or
     * degrading the authenticated user's permission level.
     */
    public class ForbiddenException extends RuntimeException {
    
        private static final long serialVersionUID = 1L;
    
        public ForbiddenException(final String arg0) {
          super(arg0);
        }
    }
    
## Class MethodNotAllowedException



    /**
     * Thrown when a method was used that is not supported by this endpoint.
     */
    public class MethodNotAllowedException extends RuntimeException {
    
        private static final long serialVersionUID = 1L;
    
        public MethodNotAllowedException(final String arg0) {
          super(arg0);
        }
    }
    
	
## Class UnsupportedMediaTypeException



    /**
     * The request entity has a Content-Type that the server does not support.
     * Some Jenkins REST API accept application/json format, but
     * check the individual resource documentation for more details. Additionally,
     * double-check that you are setting the Content-Type header correctly on your
     * request (e.g. using -H "Content-Type: application/json" in cURL).
     */
    public class UnsupportedMediaTypeException extends RuntimeException {
    
        private static final long serialVersionUID = a1L;
    
        public UnsupportedMediaTypeException(final String arg0) {
          super(arg0);
        }
    }
    

# com.cdancy.jenkins.rest.fallbacks

## Class JenkinsFallbacks


	public final class JenkinsFallbacks {

		public static final class SystemInfoOnError implements Fallback<Object> {
			@Override
			public Object createOrPropagate(final Throwable throwable) {
				checkNotNull(throwable, "throwable");
				return createSystemInfoFromErrors(getErrors(throwable));
			}
		}

		public static final class RequestStatusOnError implements Fallback<Object> {
			@Override
			public Object createOrPropagate(final Throwable throwable) {
				checkNotNull(throwable, "throwable");
				try {
					return RequestStatus.create(false, getErrors(throwable));
				} catch (JsonSyntaxException e) {
					return RequestStatus.create(false, getErrors(e));
				}
			}
		}

		public static final class IntegerResponseOnError implements Fallback<Object> {
			@Override
			public Object createOrPropagate(final Throwable throwable) {
				checkNotNull(throwable, "throwable");
				try {
					return IntegerResponse.create(null, getErrors(throwable));
				} catch (JsonSyntaxException e) {
					return IntegerResponse.create(null, getErrors(e));
				}
			}
		}

		public static final class CrumbOnError implements Fallback<Object> {
			@Override
			public Object createOrPropagate(final Throwable throwable) {
				checkNotNull(throwable, "throwable");
				try {
					return Crumb.create(null, getErrors(throwable));
				} catch (JsonSyntaxException e) {
					return Crumb.create(null, getErrors(e));
				}
			}
		}

		public static final class PluginsOnError implements Fallback<Object> {
			@Override
			public Object createOrPropagate(final Throwable throwable) {
				checkNotNull(throwable, "throwable");
				try {
					return Plugins.create(null, null, getErrors(throwable));
				} catch (JsonSyntaxException e) {
					return Plugins.create(null, null, getErrors(e));
				}
			}
		}

		// fix/hack for Jenkins jira issue: JENKINS-21311
		public static final class JENKINS_21311 implements Fallback<Object> {
			@Override
			public Object createOrPropagate(final Throwable throwable) {
				checkNotNull(throwable, "throwable");
				try {
					if (throwable.getClass() == ResourceNotFoundException.class) {
						return RequestStatus.create(true, null);
					} else {
						return RequestStatus.create(false, getErrors(throwable));
					}
				} catch (JsonSyntaxException e) {
					return RequestStatus.create(false, getErrors(e));
				}
			}
		}

		public static SystemInfo createSystemInfoFromErrors(final List<Error> errors) {
			final String illegalValue = "-1";
			return SystemInfo.create(illegalValue, illegalValue, illegalValue,
					illegalValue, illegalValue, illegalValue, errors);
		}

		/**
		 * Parse list of Error's from generic Exception.
		 *
		 * @param output Exception containing error data
		 * @return List of culled Error's
		 */
		public static List<Error> getErrors(final Exception output) {
			final Error error = Error.create(null, output.getMessage(),
					output.getClass().getName());
			return Lists.newArrayList(error);
		}

		/**
		 * Parse list of Error's from output.
		 *
		 * @param output Throwable containing error data
		 * @return List of culled Error's
		 */
		public static List<Error> getErrors(final Throwable output) {

			final List<Error> errors = Lists.newArrayList();

			String context = null;
			String message = output.getMessage();
			final String [] messageParts = output.getMessage().split("->");
			switch (messageParts.length) {
				case 1: message = messageParts[0].trim(); break;
				case 3: context = messageParts[0].trim(); message = messageParts[2].trim(); break;
			}

			final Error error = Error.create(context, message, output.getClass().getCanonicalName());
			errors.add(error);

			return errors;
		}
	}


# com.cdancy.jenkins.rest.features

## Interface CrumbIssuerApi

@RequestFilters(JenkinsNoCrumbAuthenticationFilter.class)
@Path("/crumbIssuer/api/xml")
public interface CrumbIssuerApi {

    @Named("crumb-issuer:crumb")
    @Fallback(JenkinsFallbacks.CrumbOnError.class)
    @ResponseParser(CrumbParser.class)
    @QueryParams(keys = { "xpath" }, values = { "concat(//crumbRequestField,\":\",//crumb)" })
    @Consumes(MediaType.TEXT_PLAIN)
    @GET
    Crumb crumb();
}


## Interface JobsApi

	@RequestFilters(JenkinsAuthenticationFilter.class)
	@Path("/")
	public interface JobsApi {

		@Named("jobs:get-jobs")
		@Path("{folderPath}api/json")
		@Fallback(Fallbacks.NullOnNotFoundOr404.class)
		@Consumes(MediaType.APPLICATION_JSON)
		@GET
		JobList jobList(@PathParam("folderPath") @ParamParser(FolderPathParser.class) String folderPath);

		@Named("jobs:job-info")
		@Path("{optionalFolderPath}job/{name}/api/json")
		@Fallback(Fallbacks.NullOnNotFoundOr404.class)
		@Consumes(MediaType.APPLICATION_JSON)
		@GET
		JobInfo jobInfo(@Nullable @PathParam("optionalFolderPath") @ParamParser(OptionalFolderPathParser.class) String optionalFolderPath,
						@PathParam("name") String jobName);

		@Named("jobs:artifact")
		@Path("{optionalFolderPath}job/{name}/{number}/api/json")
		@Fallback(Fallbacks.NullOnNotFoundOr404.class)
		@Consumes(MediaType.APPLICATION_JSON)
		@GET
		BuildInfo buildInfo(@Nullable @PathParam("optionalFolderPath") @ParamParser(OptionalFolderPathParser.class) String optionalFolderPath,
							@PathParam("name") String jobName,
							@PathParam("number") int buildNumber);

		@Named("jobs:artifact")
		@Path("{optionalFolderPath}job/{name}/{number}/artifact/{relativeArtifactPath}")
		@Fallback(Fallbacks.NullOnNotFoundOr404.class)
		@Consumes(MediaType.WILDCARD)
		@GET
		InputStream artifact(@Nullable @PathParam("optionalFolderPath") @ParamParser(OptionalFolderPathParser.class) String optionalFolderPath,
							 @PathParam("name") String jobName,
							 @PathParam("number") int buildNumber,
							 @PathParam("relativeArtifactPath") String relativeArtifactPath);

		@Named("jobs:create")
		@Path("{optionalFolderPath}createItem")
		@Fallback(JenkinsFallbacks.RequestStatusOnError.class)
		@ResponseParser(RequestStatusParser.class)
		@Produces(MediaType.APPLICATION_XML)
		@Consumes(MediaType.WILDCARD)
		@Payload("{configXML}")
		@POST
		RequestStatus create(@Nullable @PathParam("optionalFolderPath") @ParamParser(OptionalFolderPathParser.class) String optionalFolderPath,
							 @QueryParam("name") String jobName,
							 @PayloadParam(value = "configXML") String configXML);

		@Named("jobs:get-config")
		@Path("{optionalFolderPath}job/{name}/config.xml")
		@Fallback(Fallbacks.NullOnNotFoundOr404.class)
		@Consumes(MediaType.TEXT_PLAIN)
		@GET
		String config(@Nullable @PathParam("optionalFolderPath") @ParamParser(OptionalFolderPathParser.class) String optionalFolderPath,
					  @PathParam("name") String jobName);

		@Named("jobs:update-config")
		@Path("{optionalFolderPath}job/{name}/config.xml")
		@Fallback(Fallbacks.FalseOnNotFoundOr404.class)
		@Produces(MediaType.APPLICATION_XML + ";charset=UTF-8")
		@Consumes(MediaType.TEXT_HTML)
		@Payload("{configXML}")
		@POST
		boolean config(@Nullable @PathParam("optionalFolderPath") @ParamParser(OptionalFolderPathParser.class) String optionalFolderPath,
					   @PathParam("name") String jobName,
					   @PayloadParam(value = "configXML") String configXML);

		@Named("jobs:get-description")
		@Path("{optionalFolderPath}job/{name}/description")
		@Fallback(Fallbacks.NullOnNotFoundOr404.class)
		@Consumes(MediaType.TEXT_PLAIN)
		@GET
		String description(@Nullable @PathParam("optionalFolderPath") @ParamParser(OptionalFolderPathParser.class) String optionalFolderPath,
						   @PathParam("name") String jobName);

		@Named("jobs:set-description")
		@Path("{optionalFolderPath}job/{name}/description")
		@Fallback(Fallbacks.FalseOnNotFoundOr404.class)
		@Consumes(MediaType.TEXT_HTML)
		@POST
		boolean description(@Nullable @PathParam("optionalFolderPath") @ParamParser(OptionalFolderPathParser.class) String optionalFolderPath,
							@PathParam("name") String jobName,
							@FormParam("description") String description);

		@Named("jobs:delete")
		@Path("{optionalFolderPath}job/{name}/doDelete")
		@Consumes(MediaType.TEXT_HTML)
		@Fallback(JenkinsFallbacks.RequestStatusOnError.class)
		@ResponseParser(RequestStatusParser.class)
		@POST
		RequestStatus delete(@Nullable @PathParam("optionalFolderPath") @ParamParser(OptionalFolderPathParser.class) String optionalFolderPath,
							 @PathParam("name") String jobName);

		@Named("jobs:enable")
		@Path("{optionalFolderPath}job/{name}/enable")
		@Fallback(Fallbacks.FalseOnNotFoundOr404.class)
		@Consumes(MediaType.TEXT_HTML)
		@POST
		boolean enable(@Nullable @PathParam("optionalFolderPath") @ParamParser(OptionalFolderPathParser.class) String optionalFolderPath,
					   @PathParam("name") String jobName);

		@Named("jobs:disable")
		@Path("{optionalFolderPath}job/{name}/disable")
		@Fallback(Fallbacks.FalseOnNotFoundOr404.class)
		@Consumes(MediaType.TEXT_HTML)
		@POST
		boolean disable(@Nullable @PathParam("optionalFolderPath") @ParamParser(OptionalFolderPathParser.class) String optionalFolderPath,
						@PathParam("name") String jobName);

		@Named("jobs:build")
		@Path("{optionalFolderPath}job/{name}/build")
		@Fallback(JenkinsFallbacks.IntegerResponseOnError.class)
		@ResponseParser(LocationToQueueId.class)
		@Consumes("application/unknown")
		@POST
		IntegerResponse build(@Nullable @PathParam("optionalFolderPath") @ParamParser(OptionalFolderPathParser.class) String optionalFolderPath,
					  @PathParam("name") String jobName);

		@Named("jobs:stop-build")
		@Path("{optionalFolderPath}job/{name}/{number}/stop")
		@Fallback(JenkinsFallbacks.RequestStatusOnError.class)
		@ResponseParser(RequestStatusParser.class)
		@Consumes(MediaType.APPLICATION_JSON)
		@POST
		RequestStatus stop(@Nullable @PathParam("optionalFolderPath") @ParamParser(OptionalFolderPathParser.class) String optionalFolderPath,
								@PathParam("name") String jobName,
								@PathParam("number") int buildNumber);

		@Named("jobs:term-build")
		@Path("{optionalFolderPath}job/{name}/{number}/term")
		@Fallback(JenkinsFallbacks.RequestStatusOnError.class)
		@ResponseParser(RequestStatusParser.class)
		@Consumes(MediaType.APPLICATION_JSON)
		@POST
		RequestStatus term(@Nullable @PathParam("optionalFolderPath") @ParamParser(OptionalFolderPathParser.class) String optionalFolderPath,
								@PathParam("name") String jobName,
								@PathParam("number") int buildNumber);

		@Named("jobs:kill-build")
		@Path("{optionalFolderPath}job/{name}/{number}/kill")
		@Fallback(JenkinsFallbacks.RequestStatusOnError.class)
		@ResponseParser(RequestStatusParser.class)
		@Consumes(MediaType.APPLICATION_JSON)
		@POST
		RequestStatus kill(@Nullable @PathParam("optionalFolderPath") @ParamParser(OptionalFolderPathParser.class) String optionalFolderPath,
								@PathParam("name") String jobName,
								@PathParam("number") int buildNumber);

		@Named("jobs:build-with-params")
		@Path("{optionalFolderPath}job/{name}/buildWithParameters")
		@Fallback(JenkinsFallbacks.IntegerResponseOnError.class)
		@ResponseParser(LocationToQueueId.class)
		@Consumes("application/unknown")
		@POST
		IntegerResponse buildWithParameters(@Nullable @PathParam("optionalFolderPath") @ParamParser(OptionalFolderPathParser.class) String optionalFolderPath,
									@PathParam("name") String jobName,
									@Nullable @BinderParam(BindMapToForm.class) Map<String, List<String>> properties);

		@Named("jobs:last-build-number")
		@Path("{optionalFolderPath}job/{name}/lastBuild/buildNumber")
		@Fallback(Fallbacks.NullOnNotFoundOr404.class)
		@ResponseParser(BuildNumberToInteger.class)
		@Consumes(MediaType.TEXT_PLAIN)
		@GET
		Integer lastBuildNumber(@Nullable @PathParam("optionalFolderPath") @ParamParser(OptionalFolderPathParser.class) String optionalFolderPath,
								@PathParam("name") String jobName);

		@Named("jobs:last-build-timestamp")
		@Path("{optionalFolderPath}job/{name}/lastBuild/buildTimestamp")
		@Fallback(Fallbacks.NullOnNotFoundOr404.class)
		@Consumes(MediaType.TEXT_PLAIN)
		@GET
		String lastBuildTimestamp(@Nullable @PathParam("optionalFolderPath") @ParamParser(OptionalFolderPathParser.class) String optionalFolderPath,
								  @PathParam("name") String jobName);

		@Named("jobs:progressive-text")
		@Path("{optionalFolderPath}job/{name}/lastBuild/logText/progressiveText")
		@Fallback(Fallbacks.NullOnNotFoundOr404.class)
		@ResponseParser(OutputToProgressiveText.class)
		@Consumes(MediaType.TEXT_PLAIN)
		@GET
		ProgressiveText progressiveText(@Nullable @PathParam("optionalFolderPath") @ParamParser(OptionalFolderPathParser.class) String optionalFolderPath,
										@PathParam("name") String jobName,
										@QueryParam("start") int start);

		@Named("jobs:progressive-text")
		@Path("{optionalFolderPath}job/{name}/{number}/logText/progressiveText")
		@Fallback(Fallbacks.NullOnNotFoundOr404.class)
		@ResponseParser(OutputToProgressiveText.class)
		@Consumes(MediaType.TEXT_PLAIN)
		@GET
		ProgressiveText progressiveText(@Nullable @PathParam("optionalFolderPath") @ParamParser(OptionalFolderPathParser.class) String optionalFolderPath,
										@PathParam("name") String jobName,
										@PathParam("number") int buildNumber,
										@QueryParam("start") int start);

		@Named("jobs:rename")
		@Path("{optionalFolderPath}job/{name}/doRename")
		@Fallback(Fallbacks.FalseOnNotFoundOr404.class)
		@Consumes(MediaType.TEXT_HTML)
		@POST
		boolean rename(@Nullable @PathParam("optionalFolderPath") @ParamParser(OptionalFolderPathParser.class) String optionalFolderPath,
					   @PathParam("name") String jobName,
					   @QueryParam("newName") String newName);

		// below four apis are for "pipeline-stage-view-plugin",
		// see https://github.com/jenkinsci/pipeline-stage-view-plugin/tree/master/rest-api
		@Named("jobs:run-history")
		@Path("{optionalFolderPath}job/{name}/wfapi/runs")
		@Fallback(Fallbacks.NullOnNotFoundOr404.class)
		@Consumes(MediaType.APPLICATION_JSON)
		@GET
		List<Workflow> runHistory(@Nullable @PathParam("optionalFolderPath") @ParamParser(OptionalFolderPathParser.class) String optionalFolderPath,
								  @PathParam("name") String jobName);

		@Named("jobs:workflow")
		@Path("{optionalFolderPath}job/{name}/{number}/wfapi/describe")
		@Fallback(Fallbacks.NullOnNotFoundOr404.class)
		@Consumes(MediaType.APPLICATION_JSON)
		@GET
		Workflow workflow(@Nullable @PathParam("optionalFolderPath") @ParamParser(OptionalFolderPathParser.class) String optionalFolderPath,
			@PathParam("name") String jobName,
			@PathParam("number") int buildNumber);

		@Named("jobs:pipeline-node")
		@Path("{optionalFolderPath}job/{name}/{number}/execution/node/{nodeId}/wfapi/describe")
		@Fallback(Fallbacks.NullOnNotFoundOr404.class)
		@Consumes(MediaType.APPLICATION_JSON)
		@GET
		PipelineNode pipelineNode(@Nullable @PathParam("optionalFolderPath") @ParamParser(OptionalFolderPathParser.class) String optionalFolderPath,
			@PathParam("name") String jobName,
			@PathParam("number") int buildNumber, @PathParam("nodeId") int nodeId);

		@Named("jobs:pipeline-node-log")
		@Path("{optionalFolderPath}job/{name}/{number}/execution/node/{nodeId}/wfapi/log")
		@Fallback(Fallbacks.NullOnNotFoundOr404.class)
		@Consumes(MediaType.APPLICATION_JSON)
		@GET
		PipelineNodeLog pipelineNodeLog(@Nullable @PathParam("optionalFolderPath") @ParamParser(OptionalFolderPathParser.class) String optionalFolderPath,
								  @PathParam("name") String jobName,
								  @PathParam("number") int buildNumber, @PathParam("nodeId") int nodeId);

		@Named("jobs:testReport")
		@Path("{optionalFolderPath}job/{name}/{number}/testReport/api/json")
		@Fallback(Fallbacks.NullOnNotFoundOr404.class)
		@Consumes(MediaType.APPLICATION_JSON)
		@GET
		JsonObject testReport(@Nullable @PathParam("optionalFolderPath") @ParamParser(OptionalFolderPathParser.class) String optionalFolderPath,
			@PathParam("name") String jobName,
			@PathParam("number") int buildNumber);

	}



## Interface PluginManagerApi


	@RequestFilters(JenkinsAuthenticationFilter.class)
	@Consumes(MediaType.APPLICATION_JSON)
	@Path("/pluginManager")
	public interface PluginManagerApi {

		@Named("pluginManager:plugins")
		@Path("/api/json")
		@Fallback(JenkinsFallbacks.PluginsOnError.class)
		@GET
		Plugins plugins(@Nullable @QueryParam("depth") Integer depth,
				@Nullable @QueryParam("tree") String tree);

		@Named("pluginManager:install-necessary-plugins")
		@Path("/installNecessaryPlugins")
		@Fallback(JenkinsFallbacks.RequestStatusOnError.class)
		@ResponseParser(RequestStatusParser.class)
		@Produces(MediaType.APPLICATION_XML)
		@Payload("<jenkins><install plugin=\"{pluginID}\"/></jenkins>")
		@POST
		RequestStatus installNecessaryPlugins(@PayloadParam(value = "pluginID") String pluginID);
	}



## Interface QueueApi


	@RequestFilters(JenkinsAuthenticationFilter.class)
	@Consumes(MediaType.APPLICATION_JSON)
	@Path("/queue")
	public interface QueueApi {

		@Named("queue:queue")
		@Path("/api/json")
		@SelectJson("items")
		@GET
		List<QueueItem> queue();

		/**
		 * Get a specific queue item.
		 * 
		 * Queue items are builds that have been scheduled to run, but are waiting for a slot.
		 * You can poll the queueItem that corresponds to a build to detect whether the build is still pending or is executing.
		 * @param queueId The queue id value as returned by the JobsApi build or buildWithParameters methods.
		 * @return The queue item corresponding to the queue id.
		 */
		@Named("queue:item")
		@Path("/item/{queueId}/api/json")
		@GET
		QueueItem queueItem(@PathParam("queueId") int queueId);

		/**
		 * Cancel a queue item before it gets built.
		 * 
		 * @param id The queue id value of the queue item to cancel.
		 *           This is the value is returned by the JobsApi build or buildWithParameters methods.
		 * @return Always returns true due to JENKINS-21311.
		 */
		@Named("queue:cancel")
		@Path("/cancelItem")
		@Fallback(JenkinsFallbacks.JENKINS_21311.class)
		@ResponseParser(RequestStatusParser.class)
		@POST
		RequestStatus cancel(@FormParam("id") int id);
	}

## Interface StatisticsApi

	@RequestFilters(JenkinsAuthenticationFilter.class)
	@Consumes(MediaType.APPLICATION_JSON)
	@Path("/")
	public interface StatisticsApi {

	   @Named("statistics:overall-load")
	   @Path("/overallLoad/api/json")
	   @GET
	   OverallLoad overallLoad();
	}
	
## Interface SystemApi

	@RequestFilters(JenkinsAuthenticationFilter.class)
	@Consumes(MediaType.APPLICATION_JSON)
	@Path("/")
	public interface SystemApi {

	   @Named("system:info")
	   @Fallback(JenkinsFallbacks.SystemInfoOnError.class)
	   @ResponseParser(SystemInfoFromJenkinsHeaders.class)
	   @HEAD
	   SystemInfo systemInfo();

	   @Named("system:quiet-down")
	   @Path("quietDown")
	   @Fallback(JenkinsFallbacks.RequestStatusOnError.class)
	   @ResponseParser(RequestStatusParser.class)
	   @Consumes(MediaType.TEXT_HTML)
	   @POST
	   RequestStatus quietDown();

	   @Named("system:cancel-quiet-down")
	   @Path("cancelQuietDown")
	   @Fallback(JenkinsFallbacks.RequestStatusOnError.class)
	   @ResponseParser(RequestStatusParser.class)
	   @Consumes(MediaType.TEXT_HTML)
	   @POST
	   RequestStatus cancelQuietDown();

	}


# com.cdancy.jenkins.rest.filters

## Class JenkinsAuthenticationFilter

	@Singleton
	public class JenkinsAuthenticationFilter implements HttpRequestFilter {
		private final JenkinsAuthentication creds;
		private final JenkinsApi jenkinsApi;

		// key = Crumb, value = true if exception is ResourceNotFoundException false otherwise
		private volatile Pair<Crumb, Boolean> crumbPair = null;
		private static final String CRUMB_HEADER = "Jenkins-Crumb";

		private static final String RNFSimpleName = ResourceNotFoundException.class.getSimpleName();

		@Inject
		JenkinsAuthenticationFilter(final JenkinsAuthentication creds, final JenkinsApi jenkinsApi) {
			this.creds = creds;
			this.jenkinsApi = jenkinsApi;
		}

		@Override
		public HttpRequest filter(final HttpRequest request) throws HttpException {
			final HttpRequest.Builder<? extends HttpRequest.Builder<?>> builder = request.toBuilder();

			// Password and API Token are both Basic authentication (there is no Bearer authentication in Jenkins)
			if (creds.authType() == AuthenticationType.UsernameApiToken || creds.authType() == AuthenticationType.UsernamePassword) {
				final String authHeader = creds.authType().getAuthScheme() + " " + creds.authValue();
				builder.addHeader(HttpHeaders.AUTHORIZATION, authHeader);
			}

			// Anon and Password need the crumb and the cookie when POSTing
			if (request.getMethod().equals("POST") &&
				(creds.authType() == AuthenticationType.UsernamePassword || creds.authType() == AuthenticationType.Anonymous)
			) {
				final Pair<Crumb, Boolean> localCrumb = getCrumb();
				if (localCrumb.getKey().value() != null) {
					builder.addHeader(CRUMB_HEADER, localCrumb.getKey().value());
					Optional.ofNullable(localCrumb.getKey().sessionIdCookie())
							.ifPresent(sessionId -> builder.addHeader(HttpHeaders.COOKIE, sessionId));
				} else {
					if (!localCrumb.getValue()) {
						throw new RuntimeException("Unexpected exception being thrown: error=" + localCrumb.getKey().errors().get(0));
					}
				}
			}
			return builder.build();
		}

		private Pair<Crumb, Boolean> getCrumb() {
			Pair<Crumb, Boolean> crumbValueInit = this.crumbPair;
			if (crumbValueInit == null) {
				synchronized(this) {
					crumbValueInit = this.crumbPair;
					if (crumbValueInit == null) {
						final Crumb crumb = jenkinsApi.crumbIssuerApi().crumb();
						final Boolean isRNFE = crumb.errors().isEmpty() || crumb.errors().get(0).exceptionName().endsWith(RNFSimpleName);
						this.crumbPair = crumbValueInit = new Pair<>(crumb, isRNFE);
					}
				}
			}
			return crumbValueInit;
		}

		// simple impl/copy of javafx.util.Pair
		private static class Pair<A, B> {
			private final A a;
			private final B b;
			public Pair(final A a, final B b) {
				this.a = a;
				this.b = b;
			}
			public A getKey() {
				return a;
			}
			public B getValue() {
				return b;
			}
		}
	}


## Class JenkinsNoCrumbAuthenticationFilter


	@Singleton
	public class JenkinsNoCrumbAuthenticationFilter implements HttpRequestFilter {
		private final JenkinsAuthentication creds;

		@Inject
		JenkinsNoCrumbAuthenticationFilter(final JenkinsAuthentication creds) {
			this.creds = creds;
		}

		@Override
		public HttpRequest filter(final HttpRequest request) throws HttpException {
			if (creds.authType() == AuthenticationType.Anonymous) {
				return request;
			} else {
				final String authHeader = creds.authType().getAuthScheme() + " " + creds.authValue();
				return request.toBuilder().addHeader(HttpHeaders.AUTHORIZATION, authHeader).build();
			}
		}
	}


## Class ScrubNullFolderParam

	@Singleton
	public class ScrubNullFolderParam implements HttpRequestFilter {

		private static final String SCRUB_NULL_PARAM = "/%7B" + OPTIONAL_FOLDER_PATH_PARAM + "%7D";
		private static final String EMPTY_STRING = "";

		@Override
		public HttpRequest filter(final HttpRequest request) throws HttpException {
			final String requestPath = request.getEndpoint().getRawPath().replaceAll(SCRUB_NULL_PARAM, EMPTY_STRING);
			return request.toBuilder().fromHttpRequest(request).replacePath(requestPath).build();
		}
	}


# com.cdancy.jenkins.rest.handlers

## Class JenkinsErrorHandler


	/**
	 * Handle errors and propagate exception
	 */
	public class JenkinsErrorHandler implements HttpErrorHandler {

		@Override
		public void handleError(final HttpCommand command, final HttpResponse response) {

			Exception exception = null;
			try {
				final String message = parseMessage(command, response);

				switch (response.getStatusCode()) {
					case 400:
						if (command.getCurrentRequest().getMethod().equals("POST")) {
							if (command.getCurrentRequest().getRequestLine().contains("/createItem")) {
								if (message.contains("A job already exists with the name")) {
									exception = new ResourceAlreadyExistsException(message);
									break;
								}
							}
						}
						exception = new IllegalArgumentException(message);
						break;
					case 401:
						exception = new AuthorizationException(message);
						break;
					case 403:
						exception = new ForbiddenException(message);
						break;
					case 404:
						// When Jenkins replies to term or kill with a redirect to a non-existent URL
						// we want to return a custom error message and avoid an exception in the user code.
						if (command.getCurrentRequest().getMethod().equals("POST")) {
							final String path = command.getCurrentRequest().getEndpoint().getPath();
							if (path.endsWith("/term/")) {
								exception = new RedirectTo404Exception("The term operation does not exist for " + command.getCurrentRequest().getEndpoint().toString() + ", try stop instead.");
								break;
							} else if (path.endsWith("/kill/")) {
								exception = new RedirectTo404Exception("The kill operation does not exist for " + command.getCurrentRequest().getEndpoint().toString() + ", try stop instead.");
								break;
							}
						}
						exception = new ResourceNotFoundException(message);
						break;
					case 405:
						exception = new MethodNotAllowedException(message);
						break;
					case 409:
						exception = new ResourceAlreadyExistsException(message);
						break;
					case 415:
						exception = new UnsupportedMediaTypeException(message);
						break;
					default:
						exception = new HttpResponseException(command, response);
				}
			} catch (Exception e) {
				exception = new HttpResponseException(command, response, e);
			} finally {
				closeQuietly(response.getPayload());
				command.setException(exception);
			}
		}

		private String parseMessage(final HttpCommand command, final HttpResponse response) {
			if (response.getPayload() != null) {
				try {
					return Strings2.toStringAndClose(response.getPayload().openStream());
				} catch (IOException e) {
					throw Throwables.propagate(e);
				}
			} else {
				final String errorMessage = response.getFirstHeaderOrNull("X-Error");
				return command.getCurrentRequest().getRequestLine() +
					" -> " +
					response.getStatusLine() +
					" -> " +
					(errorMessage != null ? errorMessage : "");
			}
		}
	}


# com.cdancy.jenkins.rest.parsers

## Class BuildNumberToInteger

	/**
	 * Created by dancc on 3/11/16.
	 */
	@Singleton
	public class BuildNumberToInteger implements Function<HttpResponse, Integer> {

	   public Integer apply(HttpResponse response) {
		  return Integer.valueOf(getTextOutput(response));
	   }

	   public String getTextOutput(HttpResponse response) {
		  InputStream is = null;
		  try {
			 is = response.getPayload().openStream();
			 return CharStreams.toString(new InputStreamReader(is, Charsets.UTF_8)).trim();
		  } catch (Exception e) {
			 Throwables.propagate(e);
		  } finally {
			 if (is != null) {
				try {
				   is.close();
				} catch (Exception e) {
				   Throwables.propagate(e);
				}
			 }
		  }

		  return null;
	   }
	}


## Class CrumbParser


	/**
	 * Turn a valid response, but one that has no body, into a Crumb.
	 */
	@Singleton
	public class CrumbParser implements Function<HttpResponse, Crumb> {

		@Override
		public Crumb apply(final HttpResponse input) {
			if (input == null) {
				throw new RuntimeException("Unexpected NULL HttpResponse object");
			}

			final int statusCode = input.getStatusCode();
			if (statusCode >= 200 && statusCode < 400) {
				try {
					return Crumb.create(crumbValue(input), sessionIdCookie(input));
				} catch (final IOException e) {
					throw new RuntimeException(input.getStatusLine(), e);
				}
			} else {
				throw new RuntimeException(input.getStatusLine());
			}
		}

		private static String crumbValue(HttpResponse input) throws IOException {
			return Strings2.toStringAndClose(input.getPayload().openStream())
					.split(":")[1];
		}

		private static String sessionIdCookie(HttpResponse input) {
			return setCookieValues(input).stream()
				.filter(c -> c.startsWith(JENKINS_COOKIES_JSESSIONID))
				.findFirst()
				.orElse("");
		}

		private static Collection<String> setCookieValues(HttpResponse input) {
			Collection<String> setCookieValues = input.getHeaders().get(HttpHeaders.SET_COOKIE);
			if(setCookieValues.isEmpty()) {
				return input.getHeaders().get(HttpHeaders.SET_COOKIE.toLowerCase());
			} else {
				return setCookieValues;
			}
		}
	}


## Class FolderPathParser


	/*
	 * Turn the optionalFolderPath param to jenkins URL style
	 */
	@Singleton
	public class FolderPathParser implements Function<Object,String> {

		public static final String EMPTY_STRING = "";
		public static final String FOLDER_NAME_PREFIX = "job/";
		public static final Character FOLDER_NAME_SEPARATOR = '/';

		@Override
		public String apply(Object folderPath) {
			if(folderPath == null) {
				return EMPTY_STRING;
			}

			final StringBuilder path = new StringBuilder((String) folderPath);
			if (path.length() == 0) {
				return EMPTY_STRING;
			}

			if(path.charAt(0) == FOLDER_NAME_SEPARATOR){
				path.deleteCharAt(0);
			}
			if (path.length() == 0) {
				return EMPTY_STRING;
			}

			if(path.charAt(path.length() - 1) == FOLDER_NAME_SEPARATOR) {
				path.deleteCharAt(path.length() - 1);
			}
			if (path.length() == 0) {
				return EMPTY_STRING;
			}

			final String[] folders = path.toString().split(Character.toString(FOLDER_NAME_SEPARATOR));
			path.setLength(0);
			for(final String folder : folders) {
				path.append(FOLDER_NAME_PREFIX).append(folder).append(FOLDER_NAME_SEPARATOR);
			}
			return path.toString();
		}
	}


## Class LocationToQueueId

	/**
	 * Created by dancc on 3/11/16.
	 */
	@Singleton
	public class LocationToQueueId implements Function<HttpResponse, IntegerResponse> {

	   private static final Pattern pattern = Pattern.compile("^.*/queue/item/(\\d+)/$");

	   public IntegerResponse apply(HttpResponse response) {
		   if (response == null) {
			   throw new RuntimeException("Unexpected NULL HttpResponse object");
		   }

		  String url = response.getFirstHeaderOrNull("Location");
		  if (url != null) {
			 Matcher matcher = pattern.matcher(url);
			 if (matcher.find() && matcher.groupCount() == 1) {
				return IntegerResponse.create(Integer.valueOf(matcher.group(1)), null);
			 }
		  }
		  final Error error = Error.create(null,
			 "No queue item Location header could be found despite getting a valid HTTP response.",
			 NumberFormatException.class.getCanonicalName());
		  return IntegerResponse.create(null, Lists.newArrayList(error));
	   }
	}

## Class OptionalFolderPathParser


	/*
	 * Turn the optionalFolderPath param to jenkins URL style
	 */
	@Singleton
	public class OptionalFolderPathParser implements Function<Object,String> {

		public static final String EMPTY_STRING = "";
		public static final String FOLDER_NAME_PREFIX = "job/";
		public static final Character FOLDER_NAME_SEPARATOR = '/';

		@Override
		public String apply(Object optionalFolderPath) {
			if(optionalFolderPath == null) {
				return EMPTY_STRING;
			}

			final StringBuilder path = new StringBuilder((String) optionalFolderPath);
			if (path.length() == 0) {
				return EMPTY_STRING;
			}

			if(path.charAt(0) == FOLDER_NAME_SEPARATOR){
				path.deleteCharAt(0);
			}
			if (path.length() == 0) {
				return EMPTY_STRING;
			}

			if(path.charAt(path.length() - 1) == FOLDER_NAME_SEPARATOR) {
				path.deleteCharAt(path.length() - 1);
			}
			if (path.length() == 0) {
				return EMPTY_STRING;
			}

			final String[] folders = path.toString().split(Character.toString(FOLDER_NAME_SEPARATOR));
			path.setLength(0);
			for(final String folder : folders) {
				path.append(FOLDER_NAME_PREFIX).append(folder).append(FOLDER_NAME_SEPARATOR);
			}

			return path.toString();
		}
	}

## Class OutputToProgressiveText


	/**
	 * Created by dancc on 3/11/16.
	 */
	@Singleton
	public class OutputToProgressiveText implements Function<HttpResponse, ProgressiveText> {

	   public ProgressiveText apply(HttpResponse response) {

		  String text = getTextOutput(response);
		  int size = getTextSize(response);
		  boolean hasMoreData = getMoreData(response);
		  return ProgressiveText.create(text, size, hasMoreData);
	   }

	   public String getTextOutput(HttpResponse response) {
		   try (InputStream is = response.getPayload().openStream()) {
			   return CharStreams.toString(new InputStreamReader(is, Charsets.UTF_8));
		   } catch (Exception e) {
			   // ignore
		   }
		   // ignore

		   return null;
	   }

	   public int getTextSize(HttpResponse response) {
		  String textSize = response.getFirstHeaderOrNull("X-Text-Size");
		  return textSize != null ? Integer.parseInt(textSize) : -1;
	   }

	   public boolean getMoreData(HttpResponse response) {
		  String moreData = response.getFirstHeaderOrNull("X-More-Data");
		  return Boolean.parseBoolean(moreData);
	   }
	}
	
## Class RequestStatusParser

	/**
	 * Turn a valid response, but one that has no body, into a RequestStatus.
	 */
	@Singleton
	public class RequestStatusParser implements Function<HttpResponse, RequestStatus> {

		@Override
		public RequestStatus apply(final HttpResponse input) {
			if (input == null) {
				throw new RuntimeException("Unexpected NULL HttpResponse object");
			}

			final int statusCode = input.getStatusCode();
			if (statusCode >= 200 && statusCode < 400) {
				return RequestStatus.create(true, null);
			} else {
				throw new RuntimeException(input.getStatusLine());
			}
		}
	}

## Class SystemInfoFromJenkinsHeaders

	/**
	 * Created by dancc on 3/11/16.
	 */
	@Singleton
	public class SystemInfoFromJenkinsHeaders implements Function<HttpResponse, SystemInfo> {

		@Override
		public SystemInfo apply(HttpResponse response) {
			if (response == null) {
				throw new RuntimeException("Unexpected NULL HttpResponse object");
			}

			final int statusCode = response.getStatusCode();
			if (statusCode >= 200 && statusCode < 400) {
				return SystemInfo.create(response.getFirstHeaderOrNull("X-Hudson"), response.getFirstHeaderOrNull("X-Jenkins"),
					response.getFirstHeaderOrNull("X-Jenkins-Session"),
					response.getFirstHeaderOrNull("X-Instance-Identity"), response.getFirstHeaderOrNull("X-SSH-Endpoint"),
					response.getFirstHeaderOrNull("Server"), null);
			} else {
				throw new RuntimeException(response.getStatusLine());
			}
		}
	}

---




