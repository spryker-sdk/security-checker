# Security Checker

[![Build Status](https://github.com/spryker-sdk/security-checker/workflows/CI/badge.svg?branch=master)](https://github.com/spryker-sdk/security-checker/actions?query=workflow%3ACI+branch%3Amaster)
[![Latest Stable Version](https://poser.pugx.org/spryker-sdk/security-checker/v/stable.svg)](https://packagist.org/packages/spryker-sdk/security-checker)
[![Minimum PHP Version](https://img.shields.io/badge/php-%3E%3D%207.3-8892BF.svg)](https://php.net/)
[![PHPStan](https://img.shields.io/badge/PHPStan-level%208-brightgreen.svg?style=flat)](https://phpstan.org/)

Checks security issues in your project dependencies.
It wraps [FriendsOfPHP/security-advisories](https://github.com/FriendsOfPHP/security-advisories) and warns about any found issues.

## Installation
```
composer require --dev spryker-sdk/security-checker
```

## Configuration

After the installation you will need to enable it in your `ConsoleDependencyProvider`:
```php
use SecurityChecker\Command\SecurityCheckerCommand;

protected function getConsoleCommands(Container $container): array
{
    ...
    $commands[] = new SecurityCheckerCommand();
```

## Commands

Security checker provides the following command:
- `console security:check` - check for security issues in composer.lock file.
