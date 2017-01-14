<?php

namespace App\Services\Auth;

use App\Exceptions\NotImplementedException;
use Carbon\Carbon;
use GuzzleHttp\Client;
use Illuminate\Config\Repository;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Session\SessionManager;

class OauthGuard implements Guard {

    private $session;
    private $config;

    private $OAUTH_USER_SESSION_KEY = "oauth_user";

    private $ACCESS_TOKEN_SESSION_KEY = "accessToken";

    private $EXPIRE_DATE_SESSION_KEY = "expireDate";

    private $REFRESH_TOKEN_SESSION_KEY = "refreshToken";

    public function __construct(SessionManager $session, Repository $config) {
        $this->session = $session;
        $this->config = $config;
    }

    /**
     * Determine if the current user is authenticated.
     *
     * @return bool
     */
    public function check()
    {
        return ($this->hasAccessToken() && $this->hasUser());
    }

    public function hasUser() {
        return $this->session->has($this->OAUTH_USER_SESSION_KEY);
    }

    public function hasAccessToken() {
        if ($this->session->has($this->ACCESS_TOKEN_SESSION_KEY)) {
            if (Carbon::now() > $this->session->get($this->EXPIRE_DATE_SESSION_KEY)) {
                return $this->refreshToken();
            } else
                return true;
        } else
            return false;
    }

    public function refreshToken() {
        $responseObject = $this->getRefreshTokenResponse();
        if ($responseObject->getStatusCode() !== 200) {
            return false;
        }
        $tokenResponse = json_decode((string)$responseObject->getBody());
        $this->setCredentials($tokenResponse->access_token, $tokenResponse->refresh_token, $tokenResponse->expires_in);
        return true;
    }

    /**
     * Determine if the current user is a guest.
     *
     * @return bool
     */
    public function guest()
    {
        return !$this->check();
    }

    /**
     * Get the currently authenticated user.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function user()
    {
        return $this->session->get($this->OAUTH_USER_SESSION_KEY);
    }

    /**
     * Get the ID for the currently authenticated user.
     *
     * @return int|null
     */
    public function id()
    {
        return $this->session->get($this->OAUTH_USER_SESSION_KEY)->id;
    }

    /**
     * Validate a user's credentials.
     *
     * @param  array $credentials
     * @return bool
     */
    public function validate(array $credentials = [])
    {
        throw new NotImplementedException();
    }

    /**
     * Logins the user via the given access token
     * @param $token access token provided by the Oauth server
     * @param $expires_in the milliseconds to token expiration
     */
    public function login($code) {
        $tokenResponse = $this->getTokenResponse($code);

        $http = new Client();
        $response = $http->get($this->config->get("oauth.user_url"), [
            "headers" => [
                "Authorization" => "Bearer ". $tokenResponse->access_token
            ]
        ]);

        $userArray = json_decode((string)$response->getBody(), true);
        $user = new \App\User($userArray);
        $this->setCredentials($tokenResponse->access_token, $tokenResponse->refresh_token, $tokenResponse->expires_in);
        $this->setUser($user);
    }

    private function setCredentials($accessToken, $refreshToken, $expires) {
        $this->session->put($this->ACCESS_TOKEN_SESSION_KEY, $accessToken);
        $this->session->put($this->REFRESH_TOKEN_SESSION_KEY, $refreshToken);
        $this->session->put($this->EXPIRE_DATE_SESSION_KEY, Carbon::now()->addSeconds($expires));
    }

    /**
     * Returns the currently authenticated users token
     * @return string
     */
    public function getToken() {
        return $this->session->get($this->ACCESS_TOKEN_SESSION_KEY);
    }

    /**
     * Set the current user.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable $user
     * @return void
     */
    public function setUser(Authenticatable $user)
    {
        $this->session->put($this->OAUTH_USER_SESSION_KEY, $user);
    }

    /**
     * @param $code
     * @return array
     */
    public function getTokenResponse($code)
    {
        $http = new Client();
        $response = $http->post($this->config->get("oauth.token_url"), [
            'form_params' => [
                'grant_type' => 'authorization_code',
                'client_id' => $this->config->get("oauth.client_id"),
                'client_secret' => $this->config->get("oauth.client_secret"),
                'redirect_uri' => $this->config->get("oauth.redirect_uri"),
                'code' => $code,
            ],
        ]);
        $responeObject = json_decode((string)$response->getBody());
        return $responeObject;
    }

    /**
     * @return mixed
     */
    public function getRefreshTokenResponse()
    {
        $http = new Client();
        $tokenResponse = $http->post($this->config->get("oauth.token_url"), [
            'form_params' => [
                'grant_type' => 'refresh_token',
                'client_id' => $this->config->get("oauth.client_id"),
                'client_secret' => $this->config->get("oauth.client_secret"),
                'redirect_uri' => $this->config->get("oauth.redirect_uri"),
                'refresh_token' => $this->session->get("refreshToken"),
            ],
            "exceptions" => false
        ]);
        return $tokenResponse;
    }

}