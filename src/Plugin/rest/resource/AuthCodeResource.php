<?php

declare(strict_types=1);

namespace Drupal\simple_oauth_auth_code\Plugin\rest\resource;

use Drupal\Component\Serialization\Json;
use Drupal\consumers\Negotiator;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Session\AccountProxyInterface;
use Drupal\rest\Plugin\ResourceBase;
use Drupal\simple_oauth_auth_code\AuthCodeGeneratorInterface;
use Drupal\verification\Service\RequestVerifier;
use Psr\Log\LoggerInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Wunderwerk\JsonApiError\JsonApiErrorResponse;

/**
 * Provides a resource to get an auth code.
 *
 * This resource integrates with the verification api to
 * make sure the user verifies this action in some way.
 *
 * @RestResource(
 *   id = "simple_oauth_auth_code_auth_code",
 *   label = @Translation("Auth Code"),
 *   uri_paths = {
 *     "create" = "/simple-oauth/auth-code"
 *   }
 * )
 */
class AuthCodeResource extends ResourceBase {

  const ERR_ALREADY_LOGGED_IN = 'simple_oauth_auth_code_already_logged_in';
  const ERR_CLIENT_NOT_FOUND = 'simple_oauth_auth_code_client_not_found';
  const ERR_INVALID_PAYLOAD = 'simple_oauth_auth_code_invalid_payload';

  /**
   * Constructs a new AuthCodeResource object.
   *
   * @param array $configuration
   *   A configuration array containing information about the plugin instance.
   * @param string $plugin_id
   *   The plugin_id for the plugin instance.
   * @param mixed $plugin_definition
   *   The plugin implementation definition.
   * @param array $serializer_formats
   *   The available serialization formats.
   * @param \Psr\Log\LoggerInterface $logger
   *   A logger instance.
   * @param \Drupal\Core\Session\AccountProxyInterface $currentUser
   *   The current user.
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entityTypeManager
   *   The entity type manager.
   * @param \Drupal\verification\Service\RequestVerifier $verifier
   *   The request verifier service.
   * @param \Drupal\consumers\Negotiator $negotiator
   *   The negotiator service.
   * @param \Drupal\simple_oauth_auth_code\AuthCodeGeneratorInterface $authCodeGenerator
   *   The auth code generator service.
   */
  public function __construct(
    array $configuration,
    $plugin_id,
    $plugin_definition,
    array $serializer_formats,
    LoggerInterface $logger,
    protected AccountProxyInterface $currentUser,
    protected EntityTypeManagerInterface $entityTypeManager,
    protected RequestVerifier $verifier,
    protected Negotiator $negotiator,
    protected AuthCodeGeneratorInterface $authCodeGenerator,
  ) {
    parent::__construct($configuration, $plugin_id, $plugin_definition, $serializer_formats, $logger);
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    return new static(
      $configuration,
      $plugin_id,
      $plugin_definition,
      $container->getParameter('serializer.formats'),
      $container->get('logger.factory')->get('rest'),
      $container->get('current_user'),
      $container->get('entity_type.manager'),
      $container->get('verification.request_verifier'),
      $container->get('consumer.negotiator'),
      $container->get('simple_oauth_auth_code.auth_code_generator'),
    );
  }

  /**
   * Responds to POST requests.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The request object.
   *
   * @return \Symfony\Component\HttpFoundation\JsonResponse
   *   The response indicating success or failure.
   */
  public function post(Request $request) {
    // User must not be authenticated.
    if ($this->currentUser->isAuthenticated()) {
      return JsonApiErrorResponse::fromArray([
        'status' => Response::HTTP_BAD_REQUEST,
        'code' => self::ERR_ALREADY_LOGGED_IN,
        'title' => 'Already logged in.',
        'detail' => 'This endpoint can only be used as an unauthenticated user.',
      ]);
    }

    // Get client.
    $client = $this->negotiator->negotiateFromRequest($request);
    if (!$client) {
      return JsonApiErrorResponse::fromArray([
        'status' => Response::HTTP_INTERNAL_SERVER_ERROR,
        'code' => self::ERR_CLIENT_NOT_FOUND,
        'title' => 'Client application not found',
        'detail' => 'The client could not be negotiated from the current request.',
      ]);
    }

    // Validate payload.
    $payload = $request->getContent();
    $data = Json::decode($payload);

    if (!array_key_exists('email', $data)) {
      return new JsonResponse([
        'error' => [
          'code' => 'simple_oauth_auth_code_invalid_payload',
          'message' => 'Invalid payload: Missing field "email".',
        ],
      ], Response::HTTP_BAD_REQUEST);
    }

    if (!array_key_exists('operation', $data)) {
      return new JsonResponse([
        'error' => [
          'code' => 'simple_oauth_auth_code_invalid_payload',
          'message' => 'Invalid payload: Missing field "operation".',
        ],
      ], Response::HTTP_BAD_REQUEST);
    }

    $email = $data['email'];
    $operation = $data['operation'];

    // Load user to login.
    $result = $this->entityTypeManager->getStorage('user')->loadByProperties(['mail' => $email]);
    if (empty($result)) {
      return new JsonResponse([
        'error' => [
          'code' => 'simple_oauth_auth_code_invalid_payload',
          'message' => 'Invalid payload',
        ],
      ], Response::HTTP_BAD_REQUEST);
    }

    /** @var \Drupal\user\UserInterface $user */
    $user = reset($result);

    // Verify this login.
    $result = $this->verifier->verifyLogin($request, $operation, $user, $email);
    if ($response = $result->toErrorResponse()) {
      return $response;
    }

    // Generate auth code.
    $code = $this->authCodeGenerator->generateAuthCode($client->getClientId(), $user);
    return new JsonResponse([
      'code' => $code,
    ]);
  }

}
