<?php

declare(strict_types=1);

namespace Drupal\simple_oauth_auth_code;

use Drupal\Core\Session\AccountInterface;

/**
 * Interface for an auth code generator.
 */
interface AuthCodeGeneratorInterface {

  /**
   * Generate an auth code for the given client and user.
   *
   * @param string $clientId
   *   The client id.
   * @param \Drupal\Core\Session\AccountInterface $user
   *   The user.
   *
   * @return string
   *   The generated auth code.
   */
  public function generateAuthCode(string $clientId, AccountInterface $user): string;

}
