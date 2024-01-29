// CustomStep to provide an abstraction around accessing Vault
import java.net.HttpURLConnection
import java.net.URL
import groovy.json.JsonSlurperClassic
import groovy.json.JsonSlurper
import groovy.json.JsonOutput

@NonCPS
def authVaultJWT(Map params) {
    // Authenticate to Vault using JWT method and write a token to .vault_token
    def vaultUrl = params.vaultUrl
    def jwtToken = params.jwt
    def vaultNamespace = params.get('namespace')
    def role = params.get('role')

    final String JWT_ENDPOINT = 'auth/jwt/jenkins'

    URL url = new URL("${vaultUrl}/v1/${JWT_ENDPOINT}/login")
    HttpURLConnection connection = (HttpURLConnection) url.openConnection()
    connection.requestMethod = 'POST'
    connection.doOutput = true
    connection.setRequestProperty("Content-Type", "application/json")
    if (vaultNamespace) {
        connection.setRequestProperty("X-Vault-Namespace", vaultNamespace)
    }

    // Send payload
    Map<String, String> payload = [jwt: jwtToken]
    if (role) {
        payload['role'] = role
    }
    String jsonPayload = JsonOutput.toJson(payload)
    connection.outputStream.withWriter("UTF-8") { writer ->
        writer.write(jsonPayload)
    }

    // Handle response
    if (connection.responseCode == HttpURLConnection.HTTP_OK) {
        def jsonResponse = new JsonSlurper().parseText(connection.content.text)
        return jsonResponse.auth.client_token
    } else {
        // Handle error
        println "Failed to obtain Vault token: HTTP ${connection.responseCode}"
        return null
    }
}


@NonCPS
def vaultGetSecret(Map params) {
    // Get Vault secret using a Vault token
    def vaultUrl = params.vaultUrl
    def vaultToken = params.token
    def vaultSecretPath = params.path
    def vaultNamespace = params.get('namespace')
    def vaultMount = params.get('mount')
    def vaultSecretVersion = params.get('version')

    def SECRET_URL = "${vaultMount}/data/${vaultSecretPath}"
    if (vaultSecretVersion) {
        SECRET_URL += "?version=${vaultSecretVersion}"
    }

    URL url = new URL("${vaultUrl}/v1/${SECRET_URL}")
    HttpURLConnection connection = (HttpURLConnection) url.openConnection()
    connection.requestMethod = 'GET'
    connection.setRequestProperty("X-Vault-Token", vaultToken)
    if (vaultNamespace) {
        connection.setRequestProperty("X-Vault-Namespace", vaultNamespace)
    }

    // Handle response
    if (connection.responseCode == HttpURLConnection.HTTP_OK) {
        def jsonResponse = new groovy.json.JsonSlurperClassic().parseText(connection.inputStream.text)
        return [data: jsonResponse.data.data, status: connection.responseCode]
    } else {
        return [data: '', status: connection.responseCode]
    }
}


def call(Map params = [:], String secretPath) {
    //Get Vault secret using Vault API
    def path = params.get('path')
    def mount = params.get('mount')
    def version = params.get('version')

    if (!mount) {
        mount = 'secret'
    }

    final String CREDENTIALS_ID = 'oidc-jwt-provider'
    final String TOKEN_FILE = '.vault_token'
    final String ERROR_MSG = 'ERROR: Cannot authenticate to Vault.'

    // First attempt to use the existing token
    def vaultGetResult
    def existingToken = ''
    if (fileExists(TOKEN_FILE)) {
        existingToken = readFile(TOKEN_FILE).trim()
        vaultGetResult = vaultGetSecret path: secretPath,
                                        vaultUrl: VAULT_ADDR,
                                        namespace: VAULT_NAMESPACE,
                                        mount: mount,
                                        version: version,
                                        token: existingToken
    }

    // If the first attempt was not successful
    if (existingToken == '' || vaultGetResult.status != HttpURLConnection.HTTP_OK) {
        // Authenticate with JWT and get a new token
        def newToken = ''
        withCredentials([string(credentialsId: CREDENTIALS_ID, variable: 'IDTOKEN')]) {
            newToken = authVaultJWT jwt: IDTOKEN,
                                          vaultUrl: VAULT_ADDR,
                                          namespace: VAULT_NAMESPACE
            if (newToken) {
               writeFile file: TOKEN_FILE, text: newToken
            } else {
               error ERROR_MSG
            }
        }
        vaultGetResult = vaultGetSecret path: secretPath,
                                        vaultUrl: VAULT_ADDR,
                                        namespace: VAULT_NAMESPACE,
                                        mount: mount,
                                        version: version,
                                        token: newToken
    }

    if (vaultGetResult.status != HttpURLConnection.HTTP_OK) {
        error ERROR_MSG
    }

    return vaultGetResult.data
}
