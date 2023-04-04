<?php

declare(strict_types=1);

namespace Drupal\Tests\simple_oauth_auth_code\Kernel;

use Drupal\Component\Serialization\Json;
use Drupal\consumers\Entity\Consumer;
use Drupal\Core\Url;
use Drupal\KernelTests\Core\Entity\EntityKernelTestBase;
use Drupal\rest\Entity\RestResourceConfig;
use Drupal\user\Entity\Role;
use Drupal\user\Entity\User;
use Drupal\Core\StackMiddleware\StackedHttpKernel;
use Symfony\Component\HttpFoundation\Request;

/**
 * Test the auth code rest resource.
 */
class AuthCodeResourceTest extends EntityKernelTestBase {

  protected const CLIENT_ID = 'test_client';

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'serialization',
    'consumers',
    'rest',
    'image',
    'file',
    'options',
    'verification',
    'verification_hash',
    'simple_oauth',
    'simple_oauth_auth_code',
  ];

  /**
   * The URL to the resource.
   */
  protected Url $url;

  /**
   * The kernel.
   */
  protected StackedHttpKernel $httpKernel;

  /**
   * The client.
   */
  protected Consumer $client;

  /**
   * The client secret.
   */
  protected string $clientSecret;

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();

    $this->installEntitySchema('user');
    $this->installEntitySchema('consumer');
    $this->installEntitySchema('entity_test');
    $this->installEntitySchema('oauth2_token');
    $this->installConfig(['user']);
    $this->installConfig(['simple_oauth']);

    RestResourceConfig::create([
      'id' => 'simple_oauth_auth_code_auth_code',
      'plugin_id' => 'simple_oauth_auth_code_auth_code',
      'granularity' => RestResourceConfig::RESOURCE_GRANULARITY,
      'configuration' => [
        'methods' => ['POST'],
        'formats' => ['json'],
        'authentication' => ['cookie'],
      ],
    ])->save();

    $this->drupalSetUpCurrentUser();
    $this->setCurrentUser(User::getAnonymousUser());
    $this->grantPermissions(Role::load(Role::ANONYMOUS_ID), ['restful post simple_oauth_auth_code_auth_code']);

    $this->clientSecret = $this->randomString();

    $this->client = Consumer::create([
      'client_id' => self::CLIENT_ID,
      'label' => 'test',
      'grant_types' => [
        'authorization_code',
        'refresh_token',
      ],
      'secret' => $this->clientSecret,
      'is_default' => TRUE,
    ]);
    $this->client->save();

    $this->url = Url::fromRoute('rest.simple_oauth_auth_code_auth_code.POST');
    $this->httpKernel = $this->container->get('http_kernel');
  }

  /**
   * Test the rest resource.
   */
  public function testResource() {
    $user = $this->drupalCreateUser(['restful post simple_oauth_auth_code_auth_code']);
    $currentTime = \Drupal::time()->getRequestTime();

    /** @var \Drupal\verification_hash\VerificationHashManagerInterface $hashManager */
    $hashManager = $this->container->get('verification_hash.manager');

    $payload = [
      'operation' => 'login',
      'email' => $user->getEmail(),
    ];

    $hash = $hashManager->createHash($user, 'login', $currentTime);

    $request = $this->createJsonRequest('POST', $this->url->toString(), $payload);
    $request->headers->set('X-Verification-Hash', sprintf('%s$$%s', $hash, $currentTime));
    $response = $this->httpKernel->handle($request);

    $this->assertEquals(200, $response->getStatusCode());

    $content = $response->getContent();
    $data = Json::decode($content);

    $this->assertArrayHasKey('code', $data);

    // Abort if logged in.
    $this->setCurrentUser($user);

    $hash = $hashManager->createHash($user, 'login', $currentTime);

    $request = $this->createJsonRequest('POST', $this->url->toString(), $payload);
    $request->headers->set('X-Verification-Hash', sprintf('%s$$%s', $hash, $currentTime));
    $response = $this->httpKernel->handle($request);

    $this->assertEquals(400, $response->getStatusCode());

    // Abort if unverified.
    $this->setCurrentUser(User::getAnonymousUser());
    $request = $this->createJsonRequest('POST', $this->url->toString(), $payload);
    $response = $this->httpKernel->handle($request);

    $this->assertEquals(403, $response->getStatusCode());
  }

  /**
   * Creates a JSON request.
   *
   * @param string $method
   *   The HTTP method.
   * @param string $uri
   *   The URI.
   * @param array $content
   *   The content.
   *
   * @return \Symfony\Component\HttpFoundation\Request
   *   The request.
   */
  protected function createJsonRequest(string $method, string $uri, array $content): Request {
    $encodedContent = Json::encode($content);

    $request = Request::create($uri, $method, [], [], [], [], $encodedContent);
    $request->headers->set('Content-Type', 'application/json');

    return $request;
  }

}
