# Simple OAuth Auth Code [![Lint & Test](https://github.com/wunderwerkio/drupal-simple-oauth-auth-code/actions/workflows/main.yml/badge.svg)](https://github.com/wunderwerkio/drupal-simple-oauth-auth-code/actions/workflows/main.yml)

This modules provides a REST resource to get an OAuth authorization code for login by integrating with the [Simple OAuth](https://www.drupal.org/project/simple_oauth) and the [Verification API](https://www.drupal.org/project/verification) modules.

## Introduction

In some scenarious we want to login the user without the user actively providing the login credentials. E.g. when clicking a password reset link.

To accomplish this, this module provides a REST resource to request a OAuth authorization code, which can later be exchanged for an access token.

A authorization code can only be requested, if the request is verified via the Verification API (e.g. a verification code that has been sent to the user's e-mail account).

If the verification was successful, a authorization code is being generated for the given user.

Fore more information have a look at the [Verification API docs](https://github.com/wunderwerkio/drupal-verification).

## Setup

This module requires a configured [Consumer / Client](https://www.drupal.org/project/consumers) with the `Authorization Code Grant` enabled (the authorization code settings do not matter).

Do not forget to enable the REST resource and to set the correct permissions.

**Grant the REST resource permission to anonymous users, otherwise login will not work!**

## Example

The module only handles the generation of the auth code and requires additional modules to setup a complete workflow of handling e.g. passwordless login or a password reset.
