# Security Checker

[![Build Status](https://github.com/spryker-sdk/security-checker/workflows/CI/badge.svg?branch=master)](https://github.com/spryker-sdk/security-checker/actions?query=workflow%3ACI+branch%3Amaster)
[![Minimum PHP Version](https://img.shields.io/badge/php-%3E%3D%207.3-8892BF.svg)](https://php.net/)
[![PHPStan](https://img.shields.io/badge/PHPStan-level%208-brightgreen.svg?style=flat)](https://phpstan.org/)

Checks security issues in your project dependencies

## Installation

`composer require --dev spryker-sdk/security-checker`

## Configuration

After the installation you will need to enable it in the `ConsoleDependencyProvider`. 

## Commands

Security shecker offer the following command:
- `console security:check` - check security issue in composer.lock file.