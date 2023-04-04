<?php

declare(strict_types=1);

namespace Drupal\Tests\simple_oauth_auth_code\Kernel;

use Defuse\Crypto\Core;
use Defuse\Crypto\Crypto;
use Drupal\Core\Site\Settings;
use Drupal\simple_oauth_auth_code\AuthCodeGeneratorInterface;
use Drupal\Tests\simple_oauth\Functional\SimpleOauthTestTrait;
use Drupal\Tests\simple_oauth\Kernel\AuthorizedRequestBase;
use League\OAuth2\Server\Exception\OAuthServerException;
use Symfony\Component\HttpFoundation\Request;

/**
 * Test the th code generator.
 */
class AuthCodeGeneratorTest extends AuthorizedRequestBase {

  use SimpleOauthTestTrait;

  protected const CLIENT_ID = 'test_client';

  /**
   * Auth code generator.
   */
  protected AuthCodeGeneratorInterface $authCodeGenerator;

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'serialization',
    'consumers',
    'file',
    'options',
    'image',
    'simple_oauth',
    'simple_oauth_auth_code',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();

    $this->client
      ->set('grant_types', [
        ['value' => 'authorization_code'],
        ['value' => 'refresh_token'],
      ])
      ->save();

    $this->authCodeGenerator = $this->container->get('simple_oauth_auth_code.auth_code_generator');
  }

  /**
   * Test auth code generation.
   */
  public function testGenerateAuthCode() {
    $authCode = $this->authCodeGenerator->generateAuthCode(self::CLIENT_ID, $this->user);

    $this->assertNotNull($authCode);
    $payload = $this->decryptAuthCode($authCode);
    $now = time();

    // Get auth code expiration time from client.
    $expirationTime = (int) $this->client->get('one_time_login_auth_code_expiration')->value;

    // Create a timestamp that is $expirationTime seconds into the future.
    $timestamp = $expirationTime + $now;

    $this->assertEquals(self::CLIENT_ID, $payload['client_id']);
    $this->assertEquals($this->user->id(), $payload['user_id']);
    $this->assertEquals($timestamp, $payload['expire_time']);
    $this->assertEmpty($payload['scopes']);
    $this->assertNull($payload['redirect_uri']);

    // Exception on invalid client.
    $this->expectException(OAuthServerException::class);
    $this->authCodeGenerator->generateAuthCode('invalid-client', $this->user);
  }

  /**
   * Test the generated auth code against the authorization code grant.
   */
  public function testAuthorizationCodeGrant() {
    $authCode = $this->authCodeGenerator->generateAuthCode(self::CLIENT_ID, $this->user);

    $parameters = [
      'grant_type' => 'authorization_code',
      'client_id' => $this->client->getClientId(),
      'client_secret' => $this->clientSecret,
      'code' => $authCode,
    ];

    $request = Request::create($this->url->toString(), 'POST', $parameters);
    $response = $this->httpKernel->handle($request);

    $this->assertValidTokenResponse($response, TRUE);
  }

  /**
   * Decrypts an auth code.
   *
   * @param string $authCode
   *   The auth code to decrypt.
   *
   * @return array
   *   The decrypted auth code.
   */
  protected function decryptAuthCode(string $authCode): array {
    $decryptedPayload = Crypto::decryptWithPassword($authCode, Core::ourSubstr(Settings::getHashSalt(), 0, 32));

    return json_decode($decryptedPayload, TRUE);
  }

}
