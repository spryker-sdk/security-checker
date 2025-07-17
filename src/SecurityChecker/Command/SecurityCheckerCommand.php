<?php

/**
 * Copyright © 2019-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

declare(strict_types = 1);

namespace SecurityChecker\Command;

use Exception;
use SecurityChecker\Result;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Process\Exception\ProcessFailedException;
use Symfony\Component\Process\Exception\RuntimeException;
use Symfony\Component\Process\Process;

class SecurityCheckerCommand extends Command
{
    /**
     * @var int
     */
    protected const CODE_SUCCESS = 0;

    /**
     * @var int
     */
    protected const CODE_ERROR = 1;

    /**
     * @var string
     */
    protected const COMMAND_NAME = 'security:check';

    /**
     * @var string
     */
    protected const WGET_COMMAND_PATTERN = 'wget %s -O %s 2>&1';

    /**
     * @var string
     */
    protected const BINARY_CHECKER = 'curl -s --retry 5 --retry-delay 10 --retry-max-time 60 --connect-timeout 30 https://api.github.com/repos/fabpot/local-php-security-checker/releases/latest | grep browser_download_url | cut -d" -f4 | egrep "%s"';

    /**
     * @var string
     */
    protected const FILE_NAME = '/tmp/security-checker';

    /**
     * @var int
     */
    protected const FILE_CACHE_LIFETIME_SECONDS = 86400; // 1 day cache lifetime

    /**
     * @var string
     */
    protected const FALSE_POSITIVE_ISSUE_NUMBER = 'CVE-NONE-0001';

    /**
     * @var string
     */
    protected const OPTION_FORMAT = 'format';

    /**
     * @var string
     */
    protected const OPTION_PATH = 'path';

    /**
     * @var string
     */
    protected const EXCEPTION_MESSAGE_FAILED_TO_FIND_BINARY_URL = 'Failed to find the appropriate security checker binary URL.';

    /**
     * @var string
     */
    protected const MAC_PATTERN = '_darwin_amd64$';

    /**
     * @var string
     */
    protected const WINDOWS_PATTERN = '_windows_amd64.exe$';

    /**
     * @var string
     */
    protected const LINUX_ARM_PATTERN = '_linux_arm64$';

    /**
     * @var string
     */
    protected const LINUX_AMD_PATTERN = '_linux_amd64$';

    /**
     * @var string
     */
    protected const UNKNOWN_OSTYPE = 'unknown';

    /**
     * @var string
     */
    protected const OSTYPE_MAC = 'darwin';

    /**
     * @var string
     */
    protected const OSTYPE_WIN = 'win';

    /**
     * @var string
     */
    protected const HOSTTYPE_ARM64 = 'arm64';

    /**
     * @var string
     */
    protected const HOSTTYPE_AARCH64 = 'aarch64';

    /**
     * @return void
     */
    protected function configure(): void
    {
        $this
            ->setName(static::COMMAND_NAME)
            ->setDescription('Checks security issues in your project dependencies')
            ->addOption(
                static::OPTION_FORMAT,
                'f',
                InputOption::VALUE_OPTIONAL,
                'Set format for checker',
            )
            ->addOption(
                static::OPTION_PATH,
                'p',
                InputOption::VALUE_OPTIONAL,
                'Set path for checker',
            );
    }

    /**
     * @param \Symfony\Component\Console\Input\InputInterface $input
     * @param \Symfony\Component\Console\Output\OutputInterface $output
     *
     * @return int
     */
    public function execute(InputInterface $input, OutputInterface $output): int
    {
        $this->loadFile($output);
        $parameters = $this->getParameters($input);
        $commandOutput = $this->runCommand($parameters);
        $commandOutput = $this->markFalsePositiveResults($commandOutput);

        $result = $this->createResultFromCommandOutput($commandOutput);

        $output->writeln($result->getVulnerabilities());

        return $this->convertResultToExitCode($result, $output);
    }

    /**
     * @param \Symfony\Component\Console\Input\InputInterface $input
     *
     * @return array<string>
     */
    protected function getParameters(InputInterface $input): array
    {
        $parameters = [];

        if ($input->getOption(static::OPTION_PATH)) {
            $parameters[] = sprintf('--%s=%s', static::OPTION_PATH, $input->getOption(static::OPTION_PATH));
        }

        if ($input->getOption(static::OPTION_FORMAT)) {
            $parameters[] = sprintf('--%s=%s', static::OPTION_FORMAT, $input->getOption(static::OPTION_FORMAT));
        }

        return $parameters;
    }

    /**
     * @param \Symfony\Component\Console\Output\OutputInterface|null $output
     *
     * @throws \Symfony\Component\Process\Exception\RuntimeException
     *
     * @return void
     */
    protected function loadFile(?OutputInterface $output = null): void
    {
        if ($output->isVerbose()) {
            $output->writeln('<info>Loading security checker binary...</info>');
        }
        echo 'Loading security checker binary...' . PHP_EOL;
        // Skip if file exists and is still valid (less than 24h old)
        if ($this->isValidCachedFile()) {
            return;
        }

        // Try to clean up old file if it exists but is outdated
        if (file_exists(static::FILE_NAME)) {
            $this->removeExistingFile(static::FILE_NAME);
        }

        // Try primary method - latest release from GitHub API
        $urls = $this->getSecurityCheckerUrl();

        // If primary method fails, try fallback URL
        if (!$urls) {
            $urls = $this->getFallbackSecurityCheckerUrl();
            if (!$urls) {
                throw new RuntimeException(
                    static::EXCEPTION_MESSAGE_FAILED_TO_FIND_BINARY_URL .
                    ' Both primary and fallback methods failed.',
                );
            }
        }

        $maxAttempts = 5;
        $downloadErrors = [];
        $downloadSuccess = false;

        for ($attempt = 1; $attempt <= $maxAttempts; $attempt++) {
            exec(sprintf(static::WGET_COMMAND_PATTERN, $urls[0], static::FILE_NAME), $output, $resultCode);

            if ($resultCode === static::CODE_SUCCESS) {
                $downloadSuccess = true;

                break;
            }

            $downloadErrors = array_merge($downloadErrors, ["Attempt $attempt failed: " . implode(PHP_EOL, $output)]);
            sleep(5);
        }

        if (!$downloadSuccess) {
            throw new RuntimeException(
                "Failed to download security checker after $maxAttempts attempts. " .
                'Errors: ' . implode('; ', $downloadErrors),
            );
        }

        $this->changeFileMode();
    }

    /**
     * Checks if the cached file exists and is still valid (not older than cache lifetime)
     *
     * @return bool
     */
    protected function isValidCachedFile(): bool
    {
        if (!file_exists(static::FILE_NAME) || !is_executable(static::FILE_NAME)) {
            return false;
        }

        $fileModTime = filemtime(static::FILE_NAME);
        if ($fileModTime === false || (time() - $fileModTime) > static::FILE_CACHE_LIFETIME_SECONDS) {
            return false;
        }

        return true;
    }

    /**
     * Get security checker URL using primary method (GitHub API latest release)
     *
     * @return array<string>
     */
    protected function getSecurityCheckerUrl(): array
    {
        $urls = [];
        $resultCode = 1;

        $binaryCommand = sprintf(static::BINARY_CHECKER, $this->getBinaryCheckerPattern());

        try {
            exec($binaryCommand, $urls, $resultCode);
        } catch (Exception $e) {
            return [];
        }

        if ($resultCode !== 0 || !$urls) {
            return [];
        }

        return $urls;
    }

    /**
     * Get fallback security checker URL (direct download from GitHub release)
     *
     * @return array<string>
     */
    protected function getFallbackSecurityCheckerUrl(): array
    {
        $pattern = $this->getBinaryCheckerPattern();

        if ($pattern === static::MAC_PATTERN) {
            return $this->createFallbackUrl('_darwin_amd64');
        }

        if ($pattern === static::WINDOWS_PATTERN) {
            return $this->createFallbackUrl('_windows_amd64.exe');
        }

        if ($pattern === static::LINUX_ARM_PATTERN) {
            return $this->createFallbackUrl('_linux_arm64');
        }

        return $this->createFallbackUrl('_linux_amd64');
    }

    /**
     * @param string $binaryExtension
     *
     * @return array<string>
     */
    protected function createFallbackUrl(string $binaryExtension): array
    {
        return [
            sprintf(
                'https://github.com/fabpot/local-php-security-checker/releases/download/v1.2.0/local-php-security-checker%s',
                $binaryExtension,
            ),
        ];
    }

    /**
     * Safely removes a file if it exists
     *
     * @param string $filePath Path to the file to remove
     *
     * @return bool True if file was removed or didn't exist, false on failure
     */
    protected function removeExistingFile(string $filePath): bool
    {
        try {
            return unlink($filePath);
        } catch (Exception $e) {
            return false;
        }
    }

    /**
     * @return void
     */
    protected function changeFileMode(): void
    {
        chmod(static::FILE_NAME, 0777);
    }

    /**
     * @param array<string> $parameters
     *
     * @throws \Symfony\Component\Process\Exception\ProcessFailedException
     *
     * @return string
     */
    protected function runCommand(array $parameters): string
    {
        $parameters = array_merge([static::FILE_NAME], $parameters);

        $process = new Process($parameters);
        $process->run();

        if (!empty($process->getErrorOutput())) {
            throw new ProcessFailedException($process);
        }

        return $process->getOutput();
    }

    /**
     * @param string $commandOutput
     *
     * @return \SecurityChecker\Result
     */
    protected function createResultFromCommandOutput(string $commandOutput): Result
    {
        $count = 0;
        preg_match('/\d\spackage/m', $commandOutput, $matches);
        if ($matches) {
            $count = (int)$matches[0];
        }

        return new Result($count, $commandOutput);
    }

    /**
     * @param string $commandOutput
     *
     * @return string
     */
    protected function markFalsePositiveResults(string $commandOutput): string
    {
        if (strpos($commandOutput, static::FALSE_POSITIVE_ISSUE_NUMBER) !== false) {
            $commandOutput = str_replace(
                static::FALSE_POSITIVE_ISSUE_NUMBER,
                sprintf('<info>%s - is a false positive</info>', static::FALSE_POSITIVE_ISSUE_NUMBER),
                $commandOutput,
            );
        }

        return $commandOutput;
    }

    /**
     * @param \SecurityChecker\Result $result
     * @param \Symfony\Component\Console\Output\OutputInterface $output
     *
     * @return int
     */
    protected function convertResultToExitCode(Result $result, OutputInterface $output): int
    {
        if ($result->count() === 0) {
            return static::CODE_SUCCESS;
        }

        if (!$this->checkResultForFalsePositiveCase($result)) {
            return static::CODE_ERROR;
        }

        if ($output->isVerbose()) {
            $output->writeln(sprintf('<info>The issue about %s is a false positive result</info>', static::FALSE_POSITIVE_ISSUE_NUMBER));
            $output->writeln('<info>Check https://github.com/FriendsOfPHP/security-advisories/issues/511 for details</info>');
        }

        return static::CODE_SUCCESS;
    }

    /**
     * @param \SecurityChecker\Result $result
     *
     * @return bool
     */
    protected function checkResultForFalsePositiveCase(Result $result): bool
    {
        return $result->count() === 1 && strpos($result->getVulnerabilities(), static::FALSE_POSITIVE_ISSUE_NUMBER) !== false;
    }

    /**
     * @return string
     */
    protected function getBinaryCheckerPattern(): string
    {
        $osType = getenv('OSTYPE') ?: static::UNKNOWN_OSTYPE;
        $hostType = getenv('HOSTTYPE') ?: static::UNKNOWN_OSTYPE;

        if ($this->isMac($osType)) {
            return static::MAC_PATTERN;
        }

        if ($this->isWindows($osType)) {
            return static::WINDOWS_PATTERN;
        }

        if ($this->isArmArchitecture($hostType)) {
            return static::LINUX_ARM_PATTERN;
        }

        return static::LINUX_AMD_PATTERN;
    }

    /**
     * @param string $osType
     *
     * @return bool
     */
    protected function isMac(string $osType): bool
    {
        return strpos($osType, static::OSTYPE_MAC) !== false;
    }

    /**
     * @param string $osType
     *
     * @return bool
     */
    protected function isWindows(string $osType): bool
    {
        return strpos($osType, static::OSTYPE_WIN) !== false;
    }

    /**
     * @param string $hostType
     *
     * @return bool
     */
    protected function isArmArchitecture(string $hostType): bool
    {
        return in_array($hostType, [static::HOSTTYPE_ARM64, static::HOSTTYPE_AARCH64], true);
    }
}
