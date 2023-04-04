<?php

declare(strict_types=1);

namespace Drupal\simple_oauth_auth_code;

use Drupal\Core\Session\AccountInterface;
use Drupal\simple_oauth\Entities\UserEntity;
use Drupal\simple_oauth\Repositories\ClientRepository;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;
use Defuse\Crypto\Core;
use Drupal\Component\Serialization\Json;
use Drupal\Core\Site\Settings;
use Drupal\simple_oauth\Entities\ClientEntityInterface;
use League\OAuth2\Server\Grant\AbstractGrant;

/**
 * Service that generates an authorization code.
 *
 * This class extends the AbstractGrant to access
 * the required internal methods to generate the auth code.
 *
 * This class must not be used as a grant type!
 */
class AuthCodeGenerator extends AbstractGrant implements AuthCodeGeneratorInterface {

  /**
   * The auth code TTL.
   */
  private \DateInterval $authCodeTTL;

  /**
   * Construct new AuthCodeGenerator object.
   *
   * @param \Drupal\simple_oauth\Repositories\ClientRepository $clientRepository
   *   The client repository.
   * @param \League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface $authCodeRepository
   *   The auth code repository.
   */
  public function __construct(
    ClientRepository $clientRepository,
    AuthCodeRepositoryInterface $authCodeRepository,
  ) {
    $salt = Settings::getHashSalt();
    // The hash salt must be at least 32 characters long.
    if (Core::ourStrlen($salt) < 32) {
      throw OAuthServerException::serverError('Hash salt must be at least 32 characters long.');
    }

    $this->setEncryptionKey(Core::ourSubstr($salt, 0, 32));
    $this->setClientRepository($clientRepository);
    $this->setAuthCodeRepository($authCodeRepository);
  }

  /**
   * {@inheritdoc}
   */
  public function generateAuthCode(string $clientId, AccountInterface $user): string {
    $authCode = $this->createAuthCode($clientId, $user);

    $payload = [
      'client_id' => $authCode->getClient()->getIdentifier(),
      'redirect_uri' => $authCode->getRedirectUri(),
      'auth_code_id' => $authCode->getIdentifier(),
      'scopes' => $authCode->getScopes(),
      'user_id' => $authCode->getUserIdentifier(),
      'expire_time' => $authCode->getExpiryDateTime()->getTimestamp(),
    ];

    return $this->encrypt(Json::encode($payload));
  }

  /**
   * Creates an auth code for the given client and user.
   *
   * @param string $clientId
   *   The client id.
   * @param \Drupal\Core\Session\AccountInterface $user
   *   The user.
   *
   * @return \League\OAuth2\Server\Entities\AuthCodeEntityInterface
   *   The created auth code.
   *
   * @throws \League\OAuth2\Server\Exception\OAuthServerException
   *   If the auth code could not be created.
   */
  protected function createAuthCode(string $clientId, AccountInterface $user) {
    $clientEntity = $this->clientRepository->getClientEntity($clientId);
    if (!$clientEntity) {
      throw OAuthServerException::invalidRequest('client_id', sprintf('Client with id "%s" not found', $clientId));
    }

    if (!$clientEntity instanceof ClientEntityInterface) {
      throw new OAuthServerException('Invalid client.', 4, 'invalid_client', 401);
    }

    /** @var \Drupal\consumers\Entity\ConsumerInterface $consumer */
    $consumer = $clientEntity->getDrupalEntity();

    // Set auth code TTL from client config.
    $expirySeconds = $consumer->get('one_time_login_auth_code_expiration')->value ?? 1800;
    $this->authCodeTTL = new \DateInterval('PT' . $expirySeconds . 'S');

    // Handle scopes.
    $redirectUri = $clientEntity->getRedirectUri();
    $scopes = $this->validateScopes($this->defaultScope,
      is_array($redirectUri)
        ? reset($redirectUri)
        : $redirectUri
    );

    // User entity.
    $userEntity = new UserEntity();
    $userEntity->setIdentifier($user->id());

    // Create auth code.
    $authCode = $this->issueAuthCode(
      $this->authCodeTTL,
      $clientEntity,
      $user->id(),
      NULL,
      $scopes,
    );

    return $authCode;
  }

  /**
   * {@inheritdoc}
   */
  public function getIdentifier() {
    return 'authorization_code_generator';
  }

  /**
   * This is not a real grant.
   *
   * Disable acccess token requests.
   *
   * This class must not be used as a grant type!
   *
   * {@inheritdoc}
   *
   * @throws \LogicException
   *   Always throws this exception.
   */
  public function respondToAccessTokenRequest(
    ServerRequestInterface $request,
    ResponseTypeInterface $responseType,
    \DateInterval $accessTokenTTL
  ) {
    throw new \LogicException('This grant cannot respond to access token requests.');
  }

  /**
   * {@inheritdoc}
   */
  public function canRespondToAccessTokenRequest(ServerRequestInterface $request) {
    return FALSE;
  }

}
