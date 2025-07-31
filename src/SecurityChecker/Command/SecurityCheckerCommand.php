<?php

/**
 * Copyright © 2019-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

declare(strict_types = 1);

namespace SecurityChecker\Command;

use Exception;
use Generated\Shared\Transfer\FileSystemContentTransfer;
use Generated\Shared\Transfer\FileSystemDeleteTransfer;
use Generated\Shared\Transfer\FileSystemQueryTransfer;
use Generated\Shared\Transfer\FileSystemStreamTransfer;
use RuntimeException;
use SecurityChecker\Dependency\Service\SecurityCheckerToFileSystemServiceBridge;
use SecurityChecker\Dependency\Service\SecurityCheckerToFileSystemServiceInterface;
use SecurityChecker\Result;
use SecurityChecker\Shared\SecurityCheckerConstants;
use Spryker\Zed\Kernel\Locator;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Process\Exception\ProcessFailedException;
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
     * @var \SecurityChecker\Dependency\Service\SecurityCheckerToFileSystemServiceInterface|null
     */
    protected ?SecurityCheckerToFileSystemServiceInterface $fileSystemService = null;

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
    protected const FALLBACK_RELEASE_URL = 'https://github.com/fabpot/local-php-security-checker/releases/download/%s/local-php-security-checker%s';

    /**
     * @var string
     */
    protected const FALLBACK_VERSION = 'v2.1.3';

    /**
     * @var string
     */
    protected const LATEST_VERSION_COMMAND = 'curl -s https://api.github.com/repos/fabpot/local-php-security-checker/releases/latest | grep "tag_name" | cut -d "\"" -f 4';

    /**
     * @var string
     */
    protected const FILE_NAME = 'security-checker-binary';

    /**
     * @var string
     */
    protected const LOCAL_TMP_FILE = 'ci-security-checker/security-checker-tmp';

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
     * @return \SecurityChecker\Dependency\Service\SecurityCheckerToFileSystemServiceInterface
     */
    protected function getFileSystemService(): SecurityCheckerToFileSystemServiceInterface
    {
        if ($this->fileSystemService === null) {
            $fileSystemService = Locator::getInstance()->fileSystem()->service();
            $this->fileSystemService = new SecurityCheckerToFileSystemServiceBridge($fileSystemService);
        }

        return $this->fileSystemService;
    }

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
     * @param \Symfony\Component\Console\Output\OutputInterface $output
     *
     * @throws \Symfony\Component\Process\Exception\RuntimeException
     *
     * @return void
     */
    protected function loadFile(OutputInterface $output): void
    {
        // Step 1: Try to download the file from URL
        if ($this->tryDownloadFromUrl($output)) {
            // Step 2: If download successful and we're in CI environment with valid S3 config, save file to S3
            if ($this->isCiEnvironment() && $this->isS3ConfigurationValid()) {
                $this->uploadFileToStorage($output);
            } elseif ($this->isCiEnvironment()) {
                $output->writeln('<comment>CI environment detected but S3 configuration is incomplete - skipping upload to storage</comment>');
            }
            $this->changeFileMode();

            return;
        }

        // Step 3: If URL download failed and we're in CI with valid S3 config, try to use cached file from storage
        if ($this->isCiEnvironment() && $this->isS3ConfigurationValid() && $this->tryUseStorageFile($output)) {
            $this->changeFileMode();

            return;
        } elseif ($this->isCiEnvironment() && !$this->isS3ConfigurationValid()) {
            $output->writeln('<comment>CI environment detected but S3 configuration is incomplete - cannot use cached storage</comment>');
        }

        // Step 4: If nothing worked, throw an error
        throw new RuntimeException(
            'Failed to load security checker: unable to download from URL and no valid cached file available in storage.',
        );
    }

    /**
     * Check if we're running in CI environment
     *
     * @return bool
     */
    protected function isCiEnvironment(): bool
    {
        // Check for common CI environment variables
        return (bool)getenv('CI') ||
               (bool)getenv('GITHUB_ACTIONS') ||
               (bool)getenv('GITLAB_CI') ||
               (bool)getenv('JENKINS_URL') ||
               (bool)getenv('TRAVIS') ||
               (bool)getenv('CIRCLECI');
    }

    /**
     * Check if S3 configuration is valid for CI environment
     *
     * @return bool
     */
    protected function isS3ConfigurationValid(): bool
    {
        return !empty(getenv('AWS_ACCESS_KEY_ID')) &&
               !empty(getenv('AWS_SECRET_ACCESS_KEY')) &&
               !empty(getenv('AWS_S3_BUCKET'));
    }

    /**
     * Tries to download security checker file from URL
     *
     * @param \Symfony\Component\Console\Output\OutputInterface $output
     *
     * @return bool
     */
    protected function tryDownloadFromUrl(OutputInterface $output): bool
    {
        $urls = $this->getSecurityCheckerUrl();

        if (!$urls) {
            $urls = $this->getFallbackSecurityCheckerUrl();
            if (!$urls) {
                $output->writeln('<comment>Failed to find security checker binary URL from both primary and fallback methods</comment>');

                return false;
            }
        }

        $maxAttempts = 3;
        $downloadErrors = [];

        for ($attempt = 1; $attempt <= $maxAttempts; $attempt++) {
            $output->writeln("<info>Attempting to download security checker (attempt $attempt/$maxAttempts)...</info>");

            exec(sprintf(static::WGET_COMMAND_PATTERN, $urls[0], static::LOCAL_TMP_FILE), $outputLines, $resultCode);

            if ($resultCode === static::CODE_SUCCESS) {
                $output->writeln('<info>Security checker downloaded successfully from URL</info>');

                return true;
            }

            $downloadErrors[] = "Attempt $attempt failed: " . implode(PHP_EOL, $outputLines);
            if ($attempt >= $maxAttempts) {
                continue;
            }

            sleep(5); // Pause before next attempt
        }

        $output->writeln('<comment>Failed to download security checker from URL after ' . $maxAttempts . ' attempts</comment>');
        if ($output->isVerbose()) {
            $output->writeln('<comment>Download errors: ' . implode('; ', $downloadErrors) . '</comment>');
        }

        return false;
    }

    /**
     * Tries to use cached file from storage
     *
     * @param \Symfony\Component\Console\Output\OutputInterface $output
     *
     * @return bool
     */
    protected function tryUseStorageFile(OutputInterface $output): bool
    {
        if (!$this->isValidCachedFile()) {
            $output->writeln('<comment>No valid cached security checker file found in storage</comment>');

            return false;
        }

        $output->writeln('<info>Found valid cached security checker in storage, attempting to download...</info>');

        if (!$this->downloadFileFromStorage()) {
            $output->writeln('<error>Failed to download security checker from storage</error>');

            return false;
        }

        $output->writeln('<info>Successfully downloaded security checker from storage</info>');

        return true;
    }

    /**
     * Checks if the cached file exists and is still valid (not older than cache lifetime)
     *
     * @return bool
     */
    protected function isValidCachedFile(): bool
    {
        try {
            $fileSystemQueryTransfer = $this->createFileSystemQueryTransfer(static::FILE_NAME);

            if (!$this->getFileSystemService()->has($fileSystemQueryTransfer)) {
                return false;
            }

            $timestamp = $this->getFileSystemService()->getTimestamp($fileSystemQueryTransfer);

            if ($timestamp === null || (time() - $timestamp) > static::FILE_CACHE_LIFETIME_SECONDS) {
                return false;
            }

            return true;
        } catch (Exception $e) {
            // If filesystem is not configured or another error occurred, consider no cache exists
            return false;
        }
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
        $latestVersion = $this->getLatestReleaseVersion();

        return [
            sprintf(
                static::FALLBACK_RELEASE_URL,
                $latestVersion,
                $binaryExtension,
            ),
        ];
    }

    /**
     * Try to get the latest release version from GitHub API
     *
     * @return string
     */
    protected function getLatestReleaseVersion(): string
    {
        try {
            exec(static::LATEST_VERSION_COMMAND, $output, $resultCode);

            if ($resultCode === static::CODE_SUCCESS && !empty($output[0])) {
                return $output[0];
            }
        } catch (Exception $e) {
        }

        return static::FALLBACK_VERSION;
    }

    /**
     * Safely removes a file if it exists
     *
     * @param string $filePath
     *
     * @return bool
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
        if (!file_exists(static::LOCAL_TMP_FILE)) {
            return;
        }

        chmod(static::LOCAL_TMP_FILE, 0777);
    }

    /**
     * Downloads the security checker binary from storage to a local file
     *
     * @return bool
     */
    protected function downloadFileFromStorage(): bool
    {
        try {
            $fileSystemQueryTransfer = $this->createFileSystemQueryTransfer(static::FILE_NAME);
            $fileContent = $this->getFileSystemService()->read($fileSystemQueryTransfer);

            if (!$fileContent) {
                return false;
            }

            file_put_contents(static::LOCAL_TMP_FILE, $fileContent);

            return true;
        } catch (Exception $e) {
            // If filesystem is not configured or another error occurred
            return false;
        }
    }

    /**
     * Uploads the local security checker binary to storage
     *
     * @param \Symfony\Component\Console\Output\OutputInterface $output
     *
     * @return bool
     */
    protected function uploadFileToStorage(OutputInterface $output): bool
    {
        try {
            if (!file_exists(static::LOCAL_TMP_FILE)) {
                $output->writeln('<comment>Local security checker file not found, skipping upload to storage</comment>');

                return false;
            }

            $output->writeln('<info>Uploading security checker to storage for future use...</info>');

            $fileContent = file_get_contents(static::LOCAL_TMP_FILE);

            $fileSystemContentTransfer = $this->createFileSystemContentTransfer(static::FILE_NAME);
            $fileSystemContentTransfer->setContent($fileContent);

            $this->getFileSystemService()->write($fileSystemContentTransfer);

            $output->writeln('<info>Security checker successfully uploaded to storage</info>');

            return true;
        } catch (Exception $e) {
            // If filesystem is not configured or another error occurred
            $errorMessage = 'Failed to upload security checker to storage: ' . $e->getMessage();
            if (!$this->isS3ConfigurationValid()) {
                $errorMessage .= ' (S3 configuration incomplete - check AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_S3_BUCKET environment variables)';
            }
            $output->writeln('<comment>' . $errorMessage . '</comment>');
            if ($output->isVerbose()) {
                $output->writeln('<comment>This is not critical - the security checker will still work from the downloaded file</comment>');
            }

            return false;
        }
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
        $parameters = array_merge([static::LOCAL_TMP_FILE], $parameters);

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

    /**
     * Creates a FileSystemContentTransfer with the security checker filesystem name and path
     *
     * @param string $path
     *
     * @return \Generated\Shared\Transfer\FileSystemContentTransfer
     */
    protected function createFileSystemContentTransfer(string $path): FileSystemContentTransfer
    {
        return (new FileSystemContentTransfer())
            ->setFileSystemName(SecurityCheckerConstants::FILESYSTEM_NAME)
            ->setPath($path);
    }

    /**
     * Creates a FileSystemQueryTransfer with the security checker filesystem name and path
     *
     * @param string $path
     *
     * @return \Generated\Shared\Transfer\FileSystemQueryTransfer
     */
    protected function createFileSystemQueryTransfer(string $path): FileSystemQueryTransfer
    {
        return (new FileSystemQueryTransfer())
            ->setFileSystemName(SecurityCheckerConstants::FILESYSTEM_NAME)
            ->setPath($path);
    }

    /**
     * Creates a FileSystemStreamTransfer with the security checker filesystem name and path
     *
     * @param string $path
     *
     * @return \Generated\Shared\Transfer\FileSystemStreamTransfer
     */
    protected function createFileSystemStreamTransfer(string $path): FileSystemStreamTransfer
    {
        return (new FileSystemStreamTransfer())
            ->setFileSystemName(SecurityCheckerConstants::FILESYSTEM_NAME)
            ->setPath($path);
    }

    /**
     * Creates a FileSystemDeleteTransfer with the security checker filesystem name and path
     *
     * @param string $path
     *
     * @return \Generated\Shared\Transfer\FileSystemDeleteTransfer
     */
    protected function createFileSystemDeleteTransfer(string $path): FileSystemDeleteTransfer
    {
        return (new FileSystemDeleteTransfer())
            ->setFileSystemName(SecurityCheckerConstants::FILESYSTEM_NAME)
            ->setPath($path);
    }
}
